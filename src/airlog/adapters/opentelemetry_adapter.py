"""OpenTelemetry adapter for airlog.

Attaches :class:`~airlog.interfaces.AuditEvent` objects as span events on the
currently-active OpenTelemetry :class:`~opentelemetry.trace.Span`.  This
makes audit events visible in distributed traces alongside performance metrics
and logs – no separate pipeline needed.

The ``opentelemetry-api`` package is **optional**.  An :class:`ImportError`
is raised only when :class:`OpenTelemetryAdapter` is instantiated and the
package is absent.  Install it with::

    pip install opentelemetry-api

Example::

    from airlog import Principal
    from airlog.adapters import OpenTelemetryAdapter
    from opentelemetry import trace

    tracer = trace.get_tracer("myapp")

    with tracer.start_as_current_span("handle_request"):
        stream = OpenTelemetryAdapter(tracer=tracer)
        stream.record("login", principal=Principal("alice", "password"), resource="session")
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from airlog.interfaces import AuditEvent, AuditStream, HealthStatus, StreamFeature

if TYPE_CHECKING:
    # Import for type-checking only - no hard dependency at runtime.
    try:
        from opentelemetry.trace import Tracer
    except ImportError:  # pragma: no cover
        Tracer = Any  # type: ignore[assignment,misc]

__all__ = ["OpenTelemetryAdapter"]


class OpenTelemetryAdapter(AuditStream):
    """Audit stream that records events as OpenTelemetry span events.

    When called from within an active span, each audit event is attached as a
    *span event* (``span.add_event``).  If no span is active the event is
    silently dropped at the OTel layer – no exception is raised.

    Optionally supply a *tracer* to create a dedicated short-lived span per
    event when there is no active parent span.

    Args:
        tracer: An :class:`opentelemetry.trace.Tracer` instance, or ``None``
            to use only the currently active span without creating new ones.

    Raises:
        ImportError: At construction time when ``opentelemetry-api`` is not
            installed.

    Example::

        from opentelemetry import trace

        tracer = trace.get_tracer(__name__)
        adapter = OpenTelemetryAdapter(tracer=tracer)
    """

    def __init__(self, tracer: Tracer | None = None) -> None:
        try:
            import opentelemetry.trace as _otel_trace  # noqa: F401
        except ImportError as exc:
            raise ImportError(
                "The 'opentelemetry-api' package is required for OpenTelemetryAdapter. "
                "Install it with: pip install opentelemetry-api"
            ) from exc

        super().__init__()
        self._tracer = tracer

    @staticmethod
    def _event_attributes(event: AuditEvent) -> dict[str, Any]:
        """Build a flat OTel attribute dict from *event*."""
        return {
            "audit.event_id": event.event_id,
            "audit.sequence": event.sequence,
            "audit.timestamp_ns": event.timestamp_ns,
            "audit.action": event.action,
            "audit.principal.subject": event.principal.subject,
            "audit.principal.auth_method": event.principal.auth_method,
            "audit.resource": event.resource,
            "audit.resource_id": event.resource_id or "",
            "audit.outcome": event.outcome,
            "audit.correlation_id": event.correlation_id or "",
            "audit.checksum": event.checksum,
        }

    def emit(self, event: AuditEvent) -> None:
        """Attach *event* to the current OpenTelemetry span.

        If a *tracer* was supplied and there is no active span, a new
        ``audit_event`` span is created, the event is attached to it, and the
        span is immediately ended.

        Args:
            event: The audit event to record.
        """
        import opentelemetry.trace as otel_trace

        attributes = self._event_attributes(event)
        span = otel_trace.get_current_span()

        if span.is_recording():
            span.add_event("audit_event", attributes=attributes)
            return

        if self._tracer is not None:
            with self._tracer.start_as_current_span("audit_event") as new_span:
                new_span.add_event("audit_event", attributes=attributes)

    def health_check(self) -> HealthStatus:
        """Verify the OpenTelemetry API is importable and functional.

        Returns:
            :class:`~airlog.interfaces.HealthStatus` indicating whether the
            OTel API is available.
        """
        import time

        start = time.monotonic()
        try:
            import opentelemetry.trace as otel_trace  # noqa: F401

            latency_ms = (time.monotonic() - start) * 1_000
            return HealthStatus(healthy=True, latency_ms=latency_ms, message="OK")
        except ImportError as exc:
            latency_ms = (time.monotonic() - start) * 1_000
            return HealthStatus(healthy=False, latency_ms=latency_ms, message=str(exc))

    def supports_feature(self, feature: StreamFeature) -> bool:
        """Return capability flags for the OpenTelemetry adapter.

        Args:
            feature: The feature to query.

        Returns:
            ``True`` only for :attr:`~airlog.interfaces.StreamFeature.ASYNC`.
        """
        match feature:
            case StreamFeature.ASYNC:
                return True
            case _:
                return False

    async def aemit(self, event: AuditEvent) -> bool:
        """Asynchronously attach *event* to the current span.

        OpenTelemetry's ``span.add_event`` is synchronous and non-blocking, so
        this override calls :meth:`emit` directly without thread delegation.

        Args:
            event: The audit event to record.

        Returns:
            ``True`` always.
        """
        self.emit(event)
        return True
