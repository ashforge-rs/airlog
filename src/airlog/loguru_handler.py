"""Loguru-backed audit logger with JSON output."""

from __future__ import annotations

import sys
from typing import Any

from loguru import logger as _loguru_logger

from airlog.interfaces import AuditEvent, AuditLogger


class LoguruAuditLogger(AuditLogger):
    """Audit logger that writes JSON-formatted records via *loguru*.

    By default a single sink is added to ``sys.stderr`` using loguru's
    built-in ``serialize=True`` option, which produces newline-delimited
    JSON records.  Supply *sink* and *level* to direct output elsewhere
    (e.g. a file path or any file-like object).

    Example::

        from airlog.loguru_handler import LoguruAuditLogger

        audit = LoguruAuditLogger()
        audit.log_action("login", actor="alice", resource="session")

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
        self._logger = _loguru_logger.bind()
        self._logger.remove()
        self._logger.add(sink, level=level, serialize=True, **sink_kwargs)

    def log(self, event: AuditEvent) -> None:
        """Serialize *event* and emit it as a JSON audit record.

        Args:
            event: The audit event to record.
        """
        self._logger.info(
            "audit",
            action=event.action,
            actor=event.actor,
            resource=event.resource,
            resource_id=event.resource_id,
            outcome=event.outcome,
            timestamp=event.timestamp.isoformat(),
            **event.context,
        )
