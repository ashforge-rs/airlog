"""Scheduled retention middleware for audit streams.

:class:`RetentionMiddleware` runs lifecycle operations (``archive``,
``delete``, ``compress``) against backends that advertise the
:attr:`~airlog.interfaces.StreamFeature.RETENTION` capability.

Rules are dictionaries of the form::

    {
        "age_days": 365,
        "action": "archive",          # or "delete" / "compress"
        "target_backend": "s3",       # name known to the backend
        "filter": {"resource": "payment"},  # optional field-match filter
    }

Scheduling is driven by :class:`threading.Timer` – no external job queue
is required.  The middleware does *not* intercept the event stream; it only
operates on backends' retention APIs on a schedule.

Implement the :class:`RetentionCapableStream` ABC in your backend to opt-in.

Example::

    from airlog.retention import RetentionMiddleware, RetentionRule

    retention = RetentionMiddleware(
        backends={"s3": s3_stream},
        rules=[
            RetentionRule(age_days=365, action="archive", target_backend="s3"),
        ],
        interval_s=86_400,  # run once per day
    )
    retention.start()
    # …
    retention.stop()
"""

from __future__ import annotations

import contextlib
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from airlog.interfaces import AuditStream, StreamFeature

__all__ = [
    "RetentionCapableStream",
    "RetentionMiddleware",
    "RetentionResult",
    "RetentionRule",
]


# ---------------------------------------------------------------------------
# RetentionCapableStream
# ---------------------------------------------------------------------------


class RetentionCapableStream(AuditStream):
    """Extension of :class:`~airlog.interfaces.AuditStream` for retention-aware backends.

    Backends that support :attr:`~airlog.interfaces.StreamFeature.RETENTION`
    should subclass this (or duck-type :meth:`apply_retention`) and advertise
    the ``RETENTION`` feature flag.
    """

    def apply_retention(self, rule: RetentionRule) -> RetentionResult:
        """Execute the lifecycle operation described by *rule*.

        Args:
            rule: The :class:`RetentionRule` to apply.

        Returns:
            A :class:`RetentionResult` describing the outcome.

        Raises:
            NotImplementedError: Always – subclasses must override this.
        """
        raise NotImplementedError(  # pragma: no cover
            "RetentionCapableStream subclasses must implement apply_retention()."
        )


# ---------------------------------------------------------------------------
# RetentionRule
# ---------------------------------------------------------------------------


@dataclass
class RetentionRule:
    """Describes one retention lifecycle operation.

    Attributes:
        age_days: Events older than this many days are subject to the
            *action*.
        action: The operation to perform.  Common values: ``"archive"``,
            ``"delete"``, ``"compress"``.  The exact semantics are up to
            the backend's :meth:`~RetentionCapableStream.apply_retention`
            implementation.
        target_backend: Optional secondary backend name (e.g. the name of
            an archive tier) passed through to the backend implementation.
        filters: Optional dict of event-field equality filters.  Only events
            whose fields match all entries are subject to the rule.
        enabled: Set to ``False`` to skip this rule without removing it.
    """

    age_days: int
    action: str
    target_backend: str = ""
    filters: dict[str, Any] = field(default_factory=dict)
    enabled: bool = True


# ---------------------------------------------------------------------------
# RetentionResult
# ---------------------------------------------------------------------------


@dataclass
class RetentionResult:
    """Result of one :meth:`~RetentionCapableStream.apply_retention` call.

    Attributes:
        rule: The :class:`RetentionRule` that was applied.
        backend_name: Name of the backend the rule ran against.
        affected_count: Number of events that were acted on (estimated).
        success: ``True`` when the operation completed without error.
        message: Optional human-readable status message.
        elapsed_ms: Time taken by the backend operation in milliseconds.
        run_at_ns: Wall-clock time (nanoseconds) when the run was triggered.
    """

    rule: RetentionRule
    backend_name: str
    affected_count: int = 0
    success: bool = True
    message: str = ""
    elapsed_ms: float = 0.0
    run_at_ns: int = field(default_factory=time.time_ns)


# ---------------------------------------------------------------------------
# RetentionMiddleware
# ---------------------------------------------------------------------------


class RetentionMiddleware:
    """Runs retention rules against :class:`RetentionCapableStream` backends.

    The middleware does **not** wrap an :class:`~airlog.interfaces.AuditStream` –
    it is a standalone scheduler that calls
    :meth:`~RetentionCapableStream.apply_retention` on backends periodically.

    Args:
        backends: Mapping of ``{name: stream}`` for backends that should be
            managed.  Non-RETENTION backends are silently skipped.
        rules: The list of :class:`RetentionRule` objects to apply.
        interval_s: Seconds between scheduled runs.  Defaults to ``86_400``
            (one day).
        on_result: Optional callback invoked after each rule application with
            the :class:`RetentionResult`.

    Example::

        mw = RetentionMiddleware(
            backends={"db": db_stream},
            rules=[RetentionRule(age_days=90, action="delete")],
            interval_s=3600,
        )
        mw.start()
    """

    def __init__(
        self,
        backends: dict[str, AuditStream],
        rules: list[RetentionRule],
        *,
        interval_s: float = 86_400.0,
        on_result: Any = None,
    ) -> None:
        self._backends = dict(backends)
        self._rules = list(rules)
        self._interval_s = interval_s
        self._on_result: Any = on_result
        self._timer: threading.Timer | None = None
        self._timer_lock = threading.Lock()
        self._running = False
        self._history: list[RetentionResult] = []
        self._history_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the periodic retention scheduler.

        Safe to call multiple times; subsequent calls are no-ops.
        """
        with self._timer_lock:
            if self._running:
                return
            self._running = True
        self._schedule()

    def stop(self) -> None:
        """Stop the periodic retention scheduler.

        Any in-progress run completes before the scheduler halts.
        """
        with self._timer_lock:
            self._running = False
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None

    def _schedule(self) -> None:
        with self._timer_lock:
            if not self._running:
                return
            self._timer = threading.Timer(self._interval_s, self._run)
            self._timer.daemon = True
            self._timer.start()

    def _run(self) -> None:
        try:
            self.run_now()
        finally:
            self._schedule()

    # ------------------------------------------------------------------
    # Manual / immediate run
    # ------------------------------------------------------------------

    def run_now(self) -> list[RetentionResult]:
        """Execute all enabled rules against all eligible backends immediately.

        A backend is eligible when it both:

        * Is an instance of (or duck-types) :class:`RetentionCapableStream`, and
        * Advertises :attr:`~airlog.interfaces.StreamFeature.RETENTION` via
          :meth:`~airlog.interfaces.AuditStream.supports_feature`.

        Returns:
            A list of :class:`RetentionResult` objects – one per
            ``(backend, rule)`` pair that was executed.
        """
        results: list[RetentionResult] = []
        for backend_name, stream in self._backends.items():
            if not stream.supports_feature(StreamFeature.RETENTION):
                continue
            if not hasattr(stream, "apply_retention"):
                continue
            for rule in self._rules:
                if not rule.enabled:
                    continue
                start = time.monotonic()
                run_at = time.time_ns()
                try:
                    result = stream.apply_retention(rule)  # type: ignore[attr-defined]
                    result.backend_name = backend_name
                    result.run_at_ns = run_at
                    result.elapsed_ms = (time.monotonic() - start) * 1_000
                except Exception as exc:
                    result = RetentionResult(
                        rule=rule,
                        backend_name=backend_name,
                        success=False,
                        message=str(exc),
                        elapsed_ms=(time.monotonic() - start) * 1_000,
                        run_at_ns=run_at,
                    )
                results.append(result)
                if self._on_result is not None:
                    with contextlib.suppress(Exception):
                        self._on_result(result)

        with self._history_lock:
            self._history.extend(results)
        return results

    # ------------------------------------------------------------------
    # Inspection
    # ------------------------------------------------------------------

    def get_history(self) -> list[RetentionResult]:
        """Return a copy of all :class:`RetentionResult` objects accumulated so far.

        Returns:
            A list of :class:`RetentionResult` instances in run order.
        """
        with self._history_lock:
            return list(self._history)

    def clear_history(self) -> None:
        """Discard all accumulated :class:`RetentionResult` records."""
        with self._history_lock:
            self._history.clear()

    def add_rule(self, rule: RetentionRule) -> None:
        """Append *rule* to the active rule list.

        Args:
            rule: The :class:`RetentionRule` to add.
        """
        self._rules.append(rule)

    def remove_rule(self, rule: RetentionRule) -> None:
        """Remove *rule* from the active rule list.

        Args:
            rule: The :class:`RetentionRule` to remove.

        Raises:
            ValueError: If *rule* is not currently registered.
        """
        self._rules.remove(rule)

    def list_rules(self) -> list[RetentionRule]:
        """Return a copy of the current rule list.

        Returns:
            A shallow copy of the list of :class:`RetentionRule` objects.
        """
        return list(self._rules)
