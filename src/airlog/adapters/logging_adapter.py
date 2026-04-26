"""Standard-library :mod:`logging` adapter for airlog.

Routes :class:`~airlog.interfaces.AuditEvent` objects through Python's
built-in :mod:`logging` module so that audit records flow into any handler
that has already been configured for the application (file handlers, syslog,
cloud exporters, etc.).

This adapter has **no optional dependencies** – :mod:`logging` ships with
every Python installation.

Example::

    import logging
    from airlog import Principal
    from airlog.adapters import LoggingAdapter

    logging.basicConfig(level=logging.INFO)
    stream = LoggingAdapter(logger=logging.getLogger("myapp.audit"))
    stream.record("login", principal=Principal("alice", "password"), resource="session")
"""

from __future__ import annotations

import logging
from typing import Any

from airlog.interfaces import AuditEvent, AuditStream, HealthStatus, StreamFeature

__all__ = ["LoggingAdapter"]


class LoggingAdapter(AuditStream):
    """Audit stream that emits records via Python's :mod:`logging` module.

    Each audit event is logged as a single :class:`logging.LogRecord` at the
    configured *level*.  All event fields are available in the record's
    ``extra`` mapping so structured log handlers (e.g. python-json-logger)
    can forward them as structured attributes.

    Args:
        logger: Target :class:`logging.Logger`.  Defaults to a logger named
            ``"airlog.audit"``.
        level: Log level for audit records.  Defaults to
            :data:`logging.INFO`.

    Example::

        adapter = LoggingAdapter(logger=logging.getLogger("audit"), level=logging.WARNING)
    """

    def __init__(
        self,
        logger: logging.Logger | None = None,
        level: int = logging.INFO,
    ) -> None:
        super().__init__()
        self._logger = logger if logger is not None else logging.getLogger("airlog.audit")
        self._level = level

    def emit(self, event: AuditEvent) -> None:
        """Emit *event* as a :class:`logging.LogRecord`.

        The log message is the event's ``action`` field.  All other fields are
        injected via ``extra`` so that structured handlers can access them.

        Args:
            event: The audit event to log.
        """
        extra: dict[str, Any] = {
            "audit_event_id": event.event_id,
            "audit_sequence": event.sequence,
            "audit_timestamp_ns": event.timestamp_ns,
            "audit_action": event.action,
            "audit_principal_subject": event.principal.subject,
            "audit_principal_auth_method": event.principal.auth_method,
            "audit_resource": event.resource,
            "audit_resource_id": event.resource_id,
            "audit_outcome": event.outcome,
            "audit_correlation_id": event.correlation_id,
            "audit_context": event.context,
            "audit_checksum": event.checksum,
        }
        self._logger.log(self._level, event.action, extra=extra)

    def health_check(self) -> HealthStatus:
        """Check that the underlying logger has at least one active handler.

        Returns:
            :class:`~airlog.interfaces.HealthStatus` with ``healthy=True``
            when the logger (or any of its ancestors) has a reachable handler.
        """
        import time

        start = time.monotonic()
        # Walk the logger hierarchy to find an effective handler.
        log: logging.Logger | None = self._logger
        has_handler = False
        while log is not None:
            if log.handlers:
                has_handler = True
                break
            if not log.propagate:
                break
            log = log.parent  # type: ignore[assignment]

        latency_ms = (time.monotonic() - start) * 1_000
        if has_handler:
            return HealthStatus(healthy=True, latency_ms=latency_ms, message="OK")
        return HealthStatus(
            healthy=False,
            latency_ms=latency_ms,
            message=f"logger '{self._logger.name}' has no handlers",
        )

    def supports_feature(self, feature: StreamFeature) -> bool:
        """Return capability flags for the logging adapter.

        Only :attr:`~airlog.interfaces.StreamFeature.ASYNC` is unsupported
        (the adapter uses the default ``asyncio.to_thread`` bridge).

        Args:
            feature: The feature to query.
        """
        return False
