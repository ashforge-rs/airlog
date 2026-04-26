"""Tests for the airlog audit logging library."""

from __future__ import annotations

import io
import json
from datetime import UTC, datetime

import pytest

from airlog.interfaces import AuditEvent, AuditLogger
from airlog.loguru_handler import LoguruAuditLogger

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_logger(buf: io.StringIO) -> LoguruAuditLogger:
    """Return a :class:`LoguruAuditLogger` that writes to *buf*."""
    return LoguruAuditLogger(sink=buf)


# ---------------------------------------------------------------------------
# AuditEvent tests
# ---------------------------------------------------------------------------


class TestAuditEvent:
    def test_required_fields(self) -> None:
        event = AuditEvent(action="create", actor="alice", resource="document")
        assert event.action == "create"
        assert event.actor == "alice"
        assert event.resource == "document"

    def test_defaults(self) -> None:
        event = AuditEvent(action="delete", actor="bob", resource="file")
        assert event.outcome == "success"
        assert event.resource_id is None
        assert event.context == {}
        assert isinstance(event.timestamp, datetime)

    def test_timestamp_is_utc(self) -> None:
        event = AuditEvent(action="read", actor="carol", resource="record")
        assert event.timestamp.tzinfo is not None

    def test_custom_fields(self) -> None:
        ts = datetime(2024, 1, 1, tzinfo=UTC)
        event = AuditEvent(
            action="update",
            actor="dave",
            resource="settings",
            resource_id="42",
            outcome="failure",
            context={"reason": "permission denied"},
            timestamp=ts,
        )
        assert event.resource_id == "42"
        assert event.outcome == "failure"
        assert event.context["reason"] == "permission denied"
        assert event.timestamp == ts


# ---------------------------------------------------------------------------
# AuditLogger interface tests
# ---------------------------------------------------------------------------


class TestAuditLoggerInterface:
    """Verify that AuditLogger is an abstract base class."""

    def test_cannot_instantiate_abstract(self) -> None:
        with pytest.raises(TypeError):
            AuditLogger()  # type: ignore[abstract]

    def test_log_action_calls_log(self) -> None:
        """log_action should delegate to log()."""
        received: list[AuditEvent] = []

        class _Recorder(AuditLogger):
            def log(self, event: AuditEvent) -> None:
                received.append(event)

        recorder = _Recorder()
        recorder.log_action("login", actor="eve", resource="session", ip="10.0.0.1")

        assert len(received) == 1
        assert received[0].action == "login"
        assert received[0].actor == "eve"
        assert received[0].resource == "session"
        assert received[0].context["ip"] == "10.0.0.1"


# ---------------------------------------------------------------------------
# LoguruAuditLogger tests
# ---------------------------------------------------------------------------


class TestLoguruAuditLogger:
    def test_log_produces_json(self) -> None:
        buf = io.StringIO()
        audit = _make_logger(buf)
        event = AuditEvent(action="create", actor="frank", resource="post")
        audit.log(event)

        output = buf.getvalue().strip()
        assert output, "Expected at least one line of output"
        record = json.loads(output)
        assert record["record"]["extra"]["action"] == "create"
        assert record["record"]["extra"]["actor"] == "frank"
        assert record["record"]["extra"]["resource"] == "post"

    def test_log_action_convenience(self) -> None:
        buf = io.StringIO()
        audit = _make_logger(buf)
        audit.log_action("delete", actor="grace", resource="image", resource_id="99")

        record = json.loads(buf.getvalue().strip())
        extra = record["record"]["extra"]
        assert extra["action"] == "delete"
        assert extra["resource_id"] == "99"
        assert extra["outcome"] == "success"

    def test_failure_outcome(self) -> None:
        buf = io.StringIO()
        audit = _make_logger(buf)
        audit.log_action(
            "update",
            actor="heidi",
            resource="profile",
            outcome="failure",
            reason="validation error",
        )

        record = json.loads(buf.getvalue().strip())
        extra = record["record"]["extra"]
        assert extra["outcome"] == "failure"
        assert extra["reason"] == "validation error"

    def test_context_fields_included(self) -> None:
        buf = io.StringIO()
        audit = _make_logger(buf)
        event = AuditEvent(
            action="export",
            actor="ivan",
            resource="report",
            context={"format": "pdf", "rows": 500},
        )
        audit.log(event)

        record = json.loads(buf.getvalue().strip())
        extra = record["record"]["extra"]
        assert extra["format"] == "pdf"
        assert extra["rows"] == 500

    def test_timestamp_present(self) -> None:
        buf = io.StringIO()
        audit = _make_logger(buf)
        audit.log_action("view", actor="judy", resource="dashboard")

        record = json.loads(buf.getvalue().strip())
        assert "timestamp" in record["record"]["extra"]
