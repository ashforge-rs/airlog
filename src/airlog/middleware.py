"""Middleware pipeline for audit streams.

Provides a composable processing layer that sits between event creation and
backend emission.  Attach middleware instances to an :class:`AuditPipeline`
using :meth:`~AuditPipeline.add` – they are applied in insertion order.

Example::

    from airlog import Principal
    from airlog.middleware import AuditPipeline, EnrichmentMiddleware, RedactionMiddleware

    pipeline = (
        AuditPipeline(my_stream)
        .add(RedactionMiddleware())
        .add(EnrichmentMiddleware(env="production", region="eu-west-1"))
    )

    pipeline.record("login", principal=Principal("alice", "password"), resource="session")
"""

from __future__ import annotations

import dataclasses
import re
from typing import Any, Protocol, runtime_checkable

from airlog.interfaces import AuditEvent, AuditStream, HealthStatus, StreamFeature

__all__ = [
    "AuditMiddleware",
    "AuditPipeline",
    "EnrichmentMiddleware",
    "RedactionMiddleware",
]


# ---------------------------------------------------------------------------
# AuditMiddleware protocol
# ---------------------------------------------------------------------------


@runtime_checkable
class AuditMiddleware(Protocol):
    """Protocol for user-supplied middleware components.

    Implement :meth:`process` and pass instances to
    :meth:`AuditPipeline.add`.  Return the (possibly modified) event to
    continue the chain, or ``None`` to drop the event silently.

    Example::

        class MyMiddleware:
            def process(self, event: AuditEvent) -> AuditEvent | None:
                if event.action == "internal_healthcheck":
                    return None  # drop – do not emit
                return event
    """

    def process(self, event: AuditEvent) -> AuditEvent | None:
        """Process *event* and return a (possibly modified) event or ``None``.

        Args:
            event: The audit event travelling through the pipeline.

        Returns:
            The original or a modified :class:`~airlog.interfaces.AuditEvent`,
            or ``None`` to silently discard the event.
        """
        ...  # pragma: no cover


# ---------------------------------------------------------------------------
# AuditPipeline
# ---------------------------------------------------------------------------


class AuditPipeline(AuditStream):
    """An :class:`~airlog.interfaces.AuditStream` that runs events through a
    middleware chain before forwarding them to one or more backend streams.

    The pipeline maintains its own thread-safe sequence counter and owns the
    event identity (``event_id``, ``sequence``, ``timestamp_ns``).  Backend
    streams receive the processed event via their :meth:`~AuditStream.emit`
    method directly, bypassing their own :meth:`~AuditStream.record` logic.

    Args:
        *streams: One or more backend :class:`~airlog.interfaces.AuditStream`
            instances that will receive processed events.

    Example::

        pipeline = AuditPipeline(stream_a, stream_b).add(RedactionMiddleware())
        pipeline.record("export", principal=p, resource="report")
    """

    def __init__(self, *streams: AuditStream) -> None:
        super().__init__()
        self._streams: list[AuditStream] = list(streams)
        self._middleware: list[AuditMiddleware] = []

    def add(self, middleware: AuditMiddleware) -> AuditPipeline:
        """Append *middleware* to the processing chain.

        Middleware is applied in the order it was added.  Returns ``self`` so
        calls can be chained::

            pipeline.add(RedactionMiddleware()).add(EnrichmentMiddleware(env="prod"))

        Args:
            middleware: Any object implementing the :class:`AuditMiddleware`
                protocol.

        Returns:
            This :class:`AuditPipeline` instance.
        """
        self._middleware.append(middleware)
        return self

    def _process(self, event: AuditEvent) -> AuditEvent | None:
        """Run *event* through all middleware.  Returns ``None`` if dropped."""
        processed: AuditEvent | None = event
        for mw in self._middleware:
            if processed is None:
                return None
            processed = mw.process(processed)
        return processed

    def emit(self, event: AuditEvent) -> None:
        """Run *event* through the middleware chain and forward to all backends.

        Args:
            event: The audit event to process and emit.
        """
        processed = self._process(event)
        if processed is None:
            return
        for stream in self._streams:
            stream.emit(processed)

    async def aemit(self, event: AuditEvent) -> bool:
        """Asynchronously process *event* and forward to all backends.

        Args:
            event: The audit event to process and emit.

        Returns:
            ``True`` if the event was accepted by at least one backend
            (or all backends when none are registered), ``False`` if the
            event was dropped by middleware.
        """
        processed = self._process(event)
        if processed is None:
            return False
        results = [await stream.aemit(processed) for stream in self._streams]
        return all(results) if results else True

    def health_check(self) -> HealthStatus:
        """Return the worst-case health across all backend streams.

        If any backend reports ``healthy=False`` the pipeline itself is
        considered unhealthy.

        Returns:
            A :class:`~airlog.interfaces.HealthStatus` aggregated from all
            backends.
        """
        if not self._streams:
            return HealthStatus(healthy=True, latency_ms=0.0, message="no backends")
        statuses = [s.health_check() for s in self._streams]
        unhealthy = [s for s in statuses if not s.healthy]
        total_latency = sum(s.latency_ms for s in statuses)
        if unhealthy:
            msg = "; ".join(s.message for s in unhealthy if s.message)
            return HealthStatus(healthy=False, latency_ms=total_latency, message=msg)
        return HealthStatus(healthy=True, latency_ms=total_latency, message="OK")

    def supports_feature(self, feature: StreamFeature) -> bool:
        """Return ``True`` if **any** backend stream supports *feature*.

        Args:
            feature: The :class:`~airlog.interfaces.StreamFeature` to query.

        Returns:
            ``True`` if at least one backend advertises support.
        """
        return any(s.supports_feature(feature) for s in self._streams)


# ---------------------------------------------------------------------------
# RedactionMiddleware
# ---------------------------------------------------------------------------

_DEFAULT_PII_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Credit card numbers (Visa, MC, Amex, Discover - with optional separators)
    (re.compile(r"\b(?:\d[ -]?){13,16}\d\b"), "[REDACTED-CC]"),
    # Email addresses
    (re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"), "[REDACTED-EMAIL]"),
    # US Social Security Numbers
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED-SSN]"),
    # Generic tokens / passwords in key=value style
    (re.compile(r'(?i)(password|secret|token|api[_-]?key)\s*=\s*\S+'), r"\1=[REDACTED]"),
]


class RedactionMiddleware:
    """Remove personally-identifiable information (PII) from event context.

    Applies a list of ``(pattern, replacement)`` pairs to every string value
    in :attr:`~airlog.interfaces.AuditEvent.context`.  The event checksum is
    recomputed after redaction so :meth:`~airlog.interfaces.AuditEvent.verify`
    continues to pass.

    Default patterns redact:

    * Credit card numbers
    * Email addresses
    * US Social Security Numbers
    * Inline ``password=``, ``secret=``, ``token=``, and ``api_key=`` values

    Args:
        patterns: Override the default pattern list.  Each element is a
            ``(compiled_pattern, replacement_string)`` tuple compatible with
            :func:`re.Pattern.sub`.

    Example::

        mw = RedactionMiddleware()
        # Custom patterns only:
        mw = RedactionMiddleware(patterns=[(re.compile(r"\\d{4}"), "[NUM]")])
    """

    def __init__(
        self,
        patterns: list[tuple[re.Pattern[str], str]] | None = None,
    ) -> None:
        self._patterns = patterns if patterns is not None else _DEFAULT_PII_PATTERNS

    def _redact_value(self, value: str) -> str:
        for pattern, replacement in self._patterns:
            value = pattern.sub(replacement, value)
        return value

    def process(self, event: AuditEvent) -> AuditEvent:
        """Redact PII from string values in *event.context*.

        Args:
            event: The incoming audit event.

        Returns:
            A new :class:`~airlog.interfaces.AuditEvent` with redacted context
            and a recomputed checksum.  Returns the original *event* unchanged
            if no patterns matched.
        """
        new_context: dict[str, Any] = {}
        changed = False
        for key, val in event.context.items():
            if isinstance(val, str):
                redacted = self._redact_value(val)
                new_context[key] = redacted
                if redacted != val:
                    changed = True
            else:
                new_context[key] = val

        if not changed:
            return event

        new_checksum = AuditEvent._compute_checksum(
            event_id=event.event_id,
            sequence=event.sequence,
            timestamp_ns=event.timestamp_ns,
            action=event.action,
            principal=event.principal,
            resource=event.resource,
            resource_id=event.resource_id,
            outcome=event.outcome,
            correlation_id=event.correlation_id,
            context=new_context,
        )
        return dataclasses.replace(event, context=new_context, checksum=new_checksum)


# ---------------------------------------------------------------------------
# EnrichmentMiddleware
# ---------------------------------------------------------------------------


class EnrichmentMiddleware:
    """Inject static key-value pairs into every event's context.

    Existing context keys are **not** overwritten.  The event checksum is
    recomputed after enrichment.

    Args:
        **fields: Key-value pairs to merge into
            :attr:`~airlog.interfaces.AuditEvent.context`.

    Example::

        mw = EnrichmentMiddleware(env="production", region="eu-west-1", version="2.3.0")
    """

    def __init__(self, **fields: Any) -> None:
        self._fields: dict[str, Any] = dict(fields)

    def process(self, event: AuditEvent) -> AuditEvent:
        """Merge static fields into *event.context*.

        Existing context keys take precedence – injected values are only
        added when the key is absent from the original context.

        Args:
            event: The incoming audit event.

        Returns:
            A new :class:`~airlog.interfaces.AuditEvent` with enriched context
            and a recomputed checksum.  Returns the original *event* unchanged
            if all static keys are already present.
        """
        extra = {k: v for k, v in self._fields.items() if k not in event.context}
        if not extra:
            return event

        new_context = {**event.context, **extra}
        new_checksum = AuditEvent._compute_checksum(
            event_id=event.event_id,
            sequence=event.sequence,
            timestamp_ns=event.timestamp_ns,
            action=event.action,
            principal=event.principal,
            resource=event.resource,
            resource_id=event.resource_id,
            outcome=event.outcome,
            correlation_id=event.correlation_id,
            context=new_context,
        )
        return dataclasses.replace(event, context=new_context, checksum=new_checksum)
