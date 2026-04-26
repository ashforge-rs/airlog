"""Policy-based event routing for audit streams.

Policies let you declaratively route, require, or drop events based on
arbitrary predicates without modifying any registered backend.

Quick-start::

    from airlog.policy import PolicyRouter, PolicyAction, add_policy

    router = PolicyRouter()

    # Drop all internal health-check events
    router.add_policy(
        match=lambda e: e.action == "healthcheck",
        action=PolicyAction.DROP,
        backends=[],
    )

    # Route "payment" events exclusively to the "pci" backend
    router.add_policy(
        match=lambda e: e.resource == "payment",
        action=PolicyAction.ROUTE,
        backends=["pci"],
    )

    # Require "export" events reach at least one backend or raise
    router.add_policy(
        match=lambda e: e.action == "export",
        action=PolicyAction.REQUIRE_BACKEND,
        backends=["archive"],
    )

    router.emit(event)  # raises DeliveryError if REQUIRE_BACKEND fails
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum, auto

from airlog.interfaces import AuditEvent, AuditStream, HealthStatus, StreamFeature

__all__ = [
    "DeliveryError",
    "Policy",
    "PolicyAction",
    "PolicyRouter",
    "add_policy",
]


# ---------------------------------------------------------------------------
# PolicyAction
# ---------------------------------------------------------------------------


class PolicyAction(Enum):
    """Disposition to apply when a policy matches an event.

    Members
    -------
    DROP:
        Silently discard the event – it is never forwarded to any backend.
    ROUTE:
        Forward the event **only** to the named backends listed in the policy,
        bypassing backends not in the list.
    REQUIRE_BACKEND:
        Forward the event to the listed backends and raise
        :class:`DeliveryError` if at least one of them fails to accept it.
    """

    DROP = auto()
    ROUTE = auto()
    REQUIRE_BACKEND = auto()


# ---------------------------------------------------------------------------
# DeliveryError
# ---------------------------------------------------------------------------


class DeliveryError(RuntimeError):
    """Raised by :class:`PolicyRouter` when a ``REQUIRE_BACKEND`` policy fails.

    Attributes:
        event: The :class:`~airlog.interfaces.AuditEvent` that could not be
            delivered.
        failed_backends: Names of the backends that rejected or raised.
    """

    def __init__(self, event: AuditEvent, failed_backends: list[str]) -> None:
        self.event = event
        self.failed_backends = failed_backends
        super().__init__(
            f"Delivery failed for event {event.event_id!r} to backend(s): {failed_backends}"
        )


# ---------------------------------------------------------------------------
# Policy dataclass
# ---------------------------------------------------------------------------


@dataclass
class Policy:
    """A single routing rule.

    Attributes:
        match: Predicate that returns ``True`` when this policy applies to an
            event.
        action: What to do when *match* returns ``True``.
        backends: For :attr:`~PolicyAction.ROUTE` and
            :attr:`~PolicyAction.REQUIRE_BACKEND` – the names of the target
            backends.  Ignored for :attr:`~PolicyAction.DROP`.
        priority: Lower values are evaluated first.  Default is ``0``.
    """

    match: Callable[[AuditEvent], bool]
    action: PolicyAction
    backends: list[str] = field(default_factory=list)
    priority: int = 0


# ---------------------------------------------------------------------------
# PolicyRouter
# ---------------------------------------------------------------------------


class PolicyRouter(AuditStream):
    """An :class:`~airlog.interfaces.AuditStream` that routes events via policies.

    Events are evaluated against registered :class:`Policy` objects in
    priority order (lowest ``priority`` value first, then insertion order).
    The **first matching** policy wins.

    If no policy matches an event it is forwarded to *all* registered
    backends (default-allow semantics).

    Args:
        *streams: Named ``(name, stream)`` pairs of backends.  You can also
            register backends later with :meth:`register_backend`.

    Example::

        router = PolicyRouter(("default", LoggingAdapter()))
        router.add_policy(
            match=lambda e: e.action == "export",
            action=PolicyAction.REQUIRE_BACKEND,
            backends=["default"],
        )
        router.emit(event)
    """

    def __init__(self, *streams: tuple[str, AuditStream]) -> None:
        super().__init__()
        self._backends: dict[str, AuditStream] = {}
        self._policies: list[Policy] = []
        self._policy_lock = threading.Lock()
        for name, stream in streams:
            self._backends[name] = stream

    # ------------------------------------------------------------------
    # Backend registration
    # ------------------------------------------------------------------

    def register_backend(self, name: str, stream: AuditStream) -> None:
        """Register *stream* under *name*.

        Args:
            name: Unique string identifier for this backend.
            stream: The :class:`~airlog.interfaces.AuditStream` to register.
        """
        self._backends[name] = stream

    def deregister_backend(self, name: str) -> None:
        """Remove the backend named *name*.

        Args:
            name: The name passed to :meth:`register_backend`.

        Raises:
            KeyError: If *name* is not registered.
        """
        del self._backends[name]

    # ------------------------------------------------------------------
    # Policy management
    # ------------------------------------------------------------------

    def add_policy(
        self,
        match: Callable[[AuditEvent], bool],
        action: PolicyAction,
        backends: list[str] | None = None,
        *,
        priority: int = 0,
    ) -> Policy:
        """Register a new routing policy.

        Policies are kept sorted by *priority* (ascending) so that a policy
        with a lower numeric priority is evaluated first.

        Args:
            match: Predicate ``(event) -> bool``.  Called for every emitted
                event.
            action: The :class:`PolicyAction` to apply on a match.
            backends: List of backend names for ``ROUTE``/``REQUIRE_BACKEND``
                actions.  Pass ``[]`` or omit for ``DROP``.
            priority: Evaluation order within the policy list.

        Returns:
            The newly created :class:`Policy` instance.
        """
        policy = Policy(
            match=match,
            action=action,
            backends=list(backends or []),
            priority=priority,
        )
        with self._policy_lock:
            self._policies.append(policy)
            self._policies.sort(key=lambda p: p.priority)
        return policy

    def remove_policy(self, policy: Policy) -> None:
        """Remove a previously registered policy.

        Args:
            policy: The :class:`Policy` object returned by :meth:`add_policy`.

        Raises:
            ValueError: If *policy* is not currently registered.
        """
        with self._policy_lock:
            self._policies.remove(policy)

    def list_policies(self) -> list[Policy]:
        """Return a snapshot of all registered policies in evaluation order.

        Returns:
            A shallow copy of the policy list.
        """
        with self._policy_lock:
            return list(self._policies)

    # ------------------------------------------------------------------
    # Routing logic
    # ------------------------------------------------------------------

    def _resolve_backends(self, names: list[str]) -> list[tuple[str, AuditStream]]:
        """Return ``(name, stream)`` pairs for each name in *names*."""
        return [(n, self._backends[n]) for n in names if n in self._backends]

    def _emit_to_backends(
        self, event: AuditEvent, targets: list[tuple[str, AuditStream]]
    ) -> dict[str, bool]:
        results: dict[str, bool] = {}
        for name, stream in targets:
            try:
                stream.emit(event)
                results[name] = True
            except Exception:
                results[name] = False
        return results

    def emit(self, event: AuditEvent) -> None:
        """Evaluate policies and emit *event* to the appropriate backends.

        The first matching policy determines disposition:

        * ``DROP`` – the event is silently discarded.
        * ``ROUTE`` – the event is sent only to the named backends.
        * ``REQUIRE_BACKEND`` – the event is sent to the named backends and
          :class:`DeliveryError` is raised if any fail.

        If no policy matches, the event is forwarded to all backends.

        Args:
            event: The audit event to process.

        Raises:
            DeliveryError: When a ``REQUIRE_BACKEND`` policy cannot deliver to
                at least one target backend.
        """
        with self._policy_lock:
            policies = list(self._policies)

        for policy in policies:
            try:
                matched = policy.match(event)
            except Exception:
                matched = False

            if not matched:
                continue

            if policy.action is PolicyAction.DROP:
                return

            targets = self._resolve_backends(policy.backends)

            if policy.action is PolicyAction.ROUTE:
                self._emit_to_backends(event, targets)
                return

            if policy.action is PolicyAction.REQUIRE_BACKEND:
                results = self._emit_to_backends(event, targets)
                failed = [n for n, ok in results.items() if not ok]
                if failed or not results:
                    raise DeliveryError(event, failed)
                return

        # Default: emit to all backends
        all_backends = list(self._backends.items())
        self._emit_to_backends(event, all_backends)

    async def aemit(self, event: AuditEvent) -> bool:
        """Asynchronously evaluate policies and emit *event*.

        Mirrors the semantics of :meth:`emit` but delegates to each backend's
        :meth:`~airlog.interfaces.AuditStream.aemit`.

        Args:
            event: The audit event to process.

        Returns:
            ``True`` when all targeted backends accepted the event, ``False``
            if any failed.

        Raises:
            DeliveryError: When a ``REQUIRE_BACKEND`` policy cannot deliver.
        """
        with self._policy_lock:
            policies = list(self._policies)

        for policy in policies:
            try:
                matched = policy.match(event)
            except Exception:
                matched = False

            if not matched:
                continue

            if policy.action is PolicyAction.DROP:
                return True

            targets = self._resolve_backends(policy.backends)

            if policy.action is PolicyAction.ROUTE:
                results = await self._aemit_to_backends(event, targets)
                return all(results.values()) if results else True

            if policy.action is PolicyAction.REQUIRE_BACKEND:
                results = await self._aemit_to_backends(event, targets)
                failed = [n for n, ok in results.items() if not ok]
                if failed or not results:
                    raise DeliveryError(event, failed)
                return True

        # Default: emit to all backends
        all_backends = list(self._backends.items())
        results = await self._aemit_to_backends(event, all_backends)
        return all(results.values()) if results else True

    async def _aemit_to_backends(
        self, event: AuditEvent, targets: list[tuple[str, AuditStream]]
    ) -> dict[str, bool]:
        results: dict[str, bool] = {}
        for name, stream in targets:
            try:
                ok = await stream.aemit(event)
                results[name] = ok
            except Exception:
                results[name] = False
        return results

    def health_check(self) -> HealthStatus:
        """Return the worst-case health across all registered backends.

        Returns:
            A :class:`~airlog.interfaces.HealthStatus` aggregated from all
            backends.
        """
        if not self._backends:
            return HealthStatus(healthy=True, latency_ms=0.0, message="no backends")
        statuses = [s.health_check() for s in self._backends.values()]
        unhealthy = [s for s in statuses if not s.healthy]
        total_latency = sum(s.latency_ms for s in statuses)
        if unhealthy:
            msg = "; ".join(s.message for s in unhealthy if s.message)
            return HealthStatus(healthy=False, latency_ms=total_latency, message=msg)
        return HealthStatus(healthy=True, latency_ms=total_latency, message="OK")

    def supports_feature(self, feature: StreamFeature) -> bool:
        """Return ``True`` if **any** registered backend supports *feature*.

        Args:
            feature: The feature to query.
        """
        return any(s.supports_feature(feature) for s in self._backends.values())


# ---------------------------------------------------------------------------
# Module-level convenience helpers
# ---------------------------------------------------------------------------

#: Module-level default :class:`PolicyRouter` instance.
_default_router: PolicyRouter | None = None
_router_lock = threading.Lock()


def _get_default_router() -> PolicyRouter:
    global _default_router
    with _router_lock:
        if _default_router is None:
            _default_router = PolicyRouter()
        return _default_router


def add_policy(
    match: Callable[[AuditEvent], bool],
    action: PolicyAction,
    backends: list[str] | None = None,
    *,
    priority: int = 0,
) -> Policy:
    """Add a policy to the module-level default :class:`PolicyRouter`.

    This is a convenience wrapper so callers can configure routing without
    managing a :class:`PolicyRouter` instance explicitly.

    Args:
        match: Predicate that determines whether the policy applies.
        action: The :class:`PolicyAction` to apply.
        backends: Target backend names (for ``ROUTE``/``REQUIRE_BACKEND``).
        priority: Evaluation order within the policy list.

    Returns:
        The registered :class:`Policy`.

    Example::

        from airlog.policy import add_policy, PolicyAction

        add_policy(
            match=lambda e: e.action == "export",
            action=PolicyAction.REQUIRE_BACKEND,
            backends=["archive"],
        )
    """
    return _get_default_router().add_policy(
        match=match, action=action, backends=backends, priority=priority
    )


def get_default_router() -> PolicyRouter:
    """Return the module-level default :class:`PolicyRouter`.

    The router is created lazily on first access.

    Returns:
        The shared :class:`PolicyRouter` instance.
    """
    return _get_default_router()


def _set_default_router(router: PolicyRouter | None) -> None:
    """Replace the module-level router (intended for tests only)."""
    global _default_router
    with _router_lock:
        _default_router = router


# Expose additional public names
__all__ += ["get_default_router"]  # type: ignore[assignment]
