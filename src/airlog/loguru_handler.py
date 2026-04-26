"""Loguru-backed audit stream with JSON output."""

from __future__ import annotations

import sys
from typing import Any

from loguru import logger as _loguru_logger

from airlog.interfaces import AuditEvent, AuditStream


class LoguruAuditStream(AuditStream):
    """Audit stream that writes JSON-formatted records via *loguru*.

    By default a single sink is added to ``sys.stderr`` using loguru's
    built-in ``serialize=True`` option, which produces newline-delimited
    JSON records.  Supply *sink* and *level* to direct output elsewhere
    (e.g. a file path, ``sys.stdout``, or any file-like object).

    Example::

        import sys
        from airlog import LoguruAuditStream, Principal

        stream = LoguruAuditStream(sink=sys.stdout)
        stream.record(
            "login",
            principal=Principal(subject="alice", auth_method="password"),
            resource="session",
            correlation_id="req-abc123",
        )

    Args:
        sink: Loguru sink destination.  Defaults to ``sys.stderr``.
        level: Minimum log level for audit records.  Defaults to ``"INFO"``.
        **sink_kwargs: Additional keyword arguments forwarded to
            :func:`loguru.logger.add`.
    """

    def __init__(
        self,
        sink: Any = sys.stderr,
        level: str = "INFO",
        **sink_kwargs: Any,
    ) -> None:
        super().__init__()
        self._logger = _loguru_logger.bind()
        self._logger.remove()
        self._logger.add(sink, level=level, serialize=True, **sink_kwargs)

    def emit(self, event: AuditEvent) -> None:
        """Serialize *event* and emit it as a newline-delimited JSON audit record.

        All structured fields are stored under the loguru ``extra`` key so
        that the full audit record is recoverable from the serialized JSON.

        Args:
            event: The audit event to record.
        """
        self._logger.info(
            "audit_event",
            event_id=event.event_id,
            sequence=event.sequence,
            timestamp_ns=event.timestamp_ns,
            timestamp=event.timestamp.isoformat(),
            action=event.action,
            principal_subject=event.principal.subject,
            principal_auth_method=event.principal.auth_method,
            principal_metadata=event.principal.metadata,
            resource=event.resource,
            resource_id=event.resource_id,
            outcome=event.outcome,
            correlation_id=event.correlation_id,
            context=event.context,
            checksum=event.checksum,
        )
