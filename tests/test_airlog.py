"""Comprehensive tests for the airlog audit logging library."""

from __future__ import annotations

import dataclasses
import io
import json
import threading
import time

import pytest

from airlog.interfaces import AuditEvent, AuditStream, Principal
from airlog.loguru_handler import LoguruAuditStream

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_PRINCIPAL = Principal(subject="alice", auth_method="password")


class _RecordingStream(AuditStream):
    """Minimal AuditStream that stores emitted events in a list."""

    def __init__(self) -> None:
        super().__init__()
        self.events: list[AuditEvent] = []

    def emit(self, event: AuditEvent) -> None:
        self.events.append(event)


def _loguru_stream(buf: io.StringIO) -> LoguruAuditStream:
    return LoguruAuditStream(sink=buf)


# ---------------------------------------------------------------------------
# Principal
# ---------------------------------------------------------------------------


class TestPrincipal:
    def test_required_fields(self) -> None:
        p = Principal(subject="user-1", auth_method="password")
        assert p.subject == "user-1"
        assert p.auth_method == "password"

    def test_default_metadata_is_empty(self) -> None:
        p = Principal(subject="user-1", auth_method="jwt")
        assert p.metadata == {}

    def test_custom_metadata(self) -> None:
        p = Principal(
            subject="svc-key",
            auth_method="api_key",
            metadata={"role": "admin", "tenant": "acme"},
        )
        assert p.metadata["role"] == "admin"
        assert p.metadata["tenant"] == "acme"

    def test_frozen(self) -> None:
        p = Principal(subject="user-1", auth_method="certificate")
        with pytest.raises(dataclasses.FrozenInstanceError):
            p.subject = "other"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# AuditEvent
# ---------------------------------------------------------------------------


class TestAuditEvent:
    def _make_event(self, **overrides: object) -> AuditEvent:
        defaults: dict[str, object] = dict(
            event_id="evt-1",
            sequence=1,
            timestamp_ns=1_000_000_000,
            action="create",
            principal=_PRINCIPAL,
            resource="document",
            resource_id=None,
            outcome="success",
            correlation_id=None,
            context={},
            checksum="dummy",
        )
        defaults.update(overrides)
        return AuditEvent(**defaults)  # type: ignore[arg-type]

    def test_timestamp_property_is_utc(self) -> None:
        event = self._make_event(timestamp_ns=0)
        assert event.timestamp.tzinfo is not None
        assert event.timestamp.year == 1970

    def test_timestamp_resolution(self) -> None:
        ns = time.time_ns()
        event = self._make_event(timestamp_ns=ns)
        # Should round-trip within microsecond precision
        assert abs(event.timestamp.timestamp() - ns / 1_000_000_000) < 1e-3

    def test_frozen(self) -> None:
        event = self._make_event()
        with pytest.raises(dataclasses.FrozenInstanceError):
            event.action = "delete"  # type: ignore[misc]

    def test_compute_checksum_is_deterministic(self) -> None:
        kwargs = dict(
            event_id="evt-1",
            sequence=1,
            timestamp_ns=999,
            action="read",
            principal=_PRINCIPAL,
            resource="file",
            resource_id="f-42",
            outcome="success",
            correlation_id="req-1",
            context={"ip": "10.0.0.1"},
        )
        c1 = AuditEvent._compute_checksum(**kwargs)  # type: ignore[arg-type]
        c2 = AuditEvent._compute_checksum(**kwargs)  # type: ignore[arg-type]
        assert c1 == c2
        assert len(c1) == 64  # SHA-256 hex

    def test_compute_checksum_differs_on_field_change(self) -> None:
        base_kwargs = dict(
            event_id="evt-1",
            sequence=1,
            timestamp_ns=999,
            action="read",
            principal=_PRINCIPAL,
            resource="file",
            resource_id=None,
            outcome="success",
            correlation_id=None,
            context={},
        )
        c1 = AuditEvent._compute_checksum(**base_kwargs)  # type: ignore[arg-type]
        c2 = AuditEvent._compute_checksum(**{**base_kwargs, "action": "delete"})  # type: ignore[arg-type]
        assert c1 != c2

    def test_verify_valid_event(self) -> None:
        stream = _RecordingStream()
        event = stream.record("login", principal=_PRINCIPAL, resource="session")
        assert event.verify() is True

    def test_verify_detects_tampered_action(self) -> None:
        stream = _RecordingStream()
        event = stream.record("login", principal=_PRINCIPAL, resource="session")
        tampered = dataclasses.replace(event, action="delete")
        assert tampered.verify() is False

    def test_verify_detects_tampered_outcome(self) -> None:
        stream = _RecordingStream()
        event = stream.record("login", principal=_PRINCIPAL, resource="session")
        tampered = dataclasses.replace(event, outcome="failure")
        assert tampered.verify() is False

    def test_verify_detects_tampered_checksum(self) -> None:
        stream = _RecordingStream()
        event = stream.record("login", principal=_PRINCIPAL, resource="session")
        tampered = dataclasses.replace(event, checksum="deadbeef" * 8)
        assert tampered.verify() is False

    def test_principal_metadata_not_part_of_checksum(self) -> None:
        """Enriching metadata must not invalidate an existing checksum."""
        stream = _RecordingStream()
        event = stream.record("login", principal=_PRINCIPAL, resource="session")
        enriched_principal = dataclasses.replace(_PRINCIPAL, metadata={"reviewed_by": "soc-team"})
        enriched = dataclasses.replace(event, principal=enriched_principal)
        assert enriched.verify() is True


# ---------------------------------------------------------------------------
# AuditStream
# ---------------------------------------------------------------------------


class TestAuditStream:
    def test_cannot_instantiate_abstract(self) -> None:
        with pytest.raises(TypeError):
            AuditStream()  # type: ignore[abstract]

    def test_sequence_increments(self) -> None:
        stream = _RecordingStream()
        e1 = stream.record("a", principal=_PRINCIPAL, resource="r")
        e2 = stream.record("b", principal=_PRINCIPAL, resource="r")
        e3 = stream.record("c", principal=_PRINCIPAL, resource="r")
        assert e1.sequence == 1
        assert e2.sequence == 2
        assert e3.sequence == 3

    def test_record_all_fields(self) -> None:
        stream = _RecordingStream()
        p = Principal(subject="svc", auth_method="certificate", metadata={"env": "prod"})
        event = stream.record(
            "export",
            principal=p,
            resource="report",
            resource_id="rep-99",
            outcome="failure",
            correlation_id="req-xyz",
            reason="timeout",
        )
        assert event.action == "export"
        assert event.principal is p
        assert event.resource == "report"
        assert event.resource_id == "rep-99"
        assert event.outcome == "failure"
        assert event.correlation_id == "req-xyz"
        assert event.context["reason"] == "timeout"
        assert event.event_id  # non-empty UUID string
        assert event.timestamp_ns > 0
        assert event.checksum

    def test_record_returns_emitted_event(self) -> None:
        stream = _RecordingStream()
        returned = stream.record("read", principal=_PRINCIPAL, resource="doc")
        assert len(stream.events) == 1
        assert stream.events[0] is returned

    def test_event_id_is_unique(self) -> None:
        stream = _RecordingStream()
        ids = {stream.record("op", principal=_PRINCIPAL, resource="r").event_id for _ in range(50)}
        assert len(ids) == 50

    def test_thread_safe_sequence(self) -> None:
        """Concurrent record() calls must produce unique, gap-free sequences."""
        stream = _RecordingStream()
        n = 200
        threads = [
            threading.Thread(target=stream.record, args=("op", _PRINCIPAL, "r")) for _ in range(n)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        seqs = sorted(e.sequence for e in stream.events)
        assert seqs == list(range(1, n + 1))

    def test_custom_stream_implementation(self) -> None:
        """Users can implement their own AuditStream."""

        class _SyslogStream(AuditStream):
            def __init__(self) -> None:
                super().__init__()
                self.lines: list[str] = []

            def emit(self, event: AuditEvent) -> None:
                self.lines.append(f"[{event.sequence}] {event.action} by {event.principal.subject}")

        s = _SyslogStream()
        s.record("delete", principal=Principal(subject="bob", auth_method="jwt"), resource="file")
        assert s.lines[0] == "[1] delete by bob"


# ---------------------------------------------------------------------------
# LoguruAuditStream
# ---------------------------------------------------------------------------


class TestLoguruAuditStream:
    def _record(
        self, buf: io.StringIO, action: str = "create", **kwargs: object
    ) -> dict[str, object]:
        stream = _loguru_stream(buf)
        stream.record(action, principal=_PRINCIPAL, resource="document", **kwargs)  # type: ignore[arg-type]
        return json.loads(buf.getvalue().strip())

    def test_output_is_valid_json(self) -> None:
        buf = io.StringIO()
        _loguru_stream(buf).record("create", principal=_PRINCIPAL, resource="doc")
        record = json.loads(buf.getvalue().strip())
        assert "record" in record

    def test_core_fields_present(self) -> None:
        buf = io.StringIO()
        extra = self._record(buf)["record"]["extra"]  # type: ignore[index]
        for field_name in (
            "event_id",
            "sequence",
            "timestamp_ns",
            "timestamp",
            "action",
            "principal_subject",
            "principal_auth_method",
            "resource",
            "outcome",
            "checksum",
        ):
            assert field_name in extra, f"Missing field: {field_name}"

    def test_action_and_resource(self) -> None:
        buf = io.StringIO()
        extra = self._record(buf, "delete")["record"]["extra"]  # type: ignore[index]
        assert extra["action"] == "delete"  # type: ignore[index]
        assert extra["resource"] == "document"  # type: ignore[index]

    def test_principal_fields(self) -> None:
        buf = io.StringIO()
        extra = self._record(buf)["record"]["extra"]  # type: ignore[index]
        assert extra["principal_subject"] == "alice"  # type: ignore[index]
        assert extra["principal_auth_method"] == "password"  # type: ignore[index]

    def test_correlation_id(self) -> None:
        buf = io.StringIO()
        extra = self._record(buf, correlation_id="req-1")["record"]["extra"]  # type: ignore[index]
        assert extra["correlation_id"] == "req-1"  # type: ignore[index]

    def test_context_nested(self) -> None:
        buf = io.StringIO()
        extra = self._record(buf, ip="10.0.0.1", rows=42)["record"]["extra"]  # type: ignore[index]
        ctx = extra["context"]  # type: ignore[index]
        assert ctx["ip"] == "10.0.0.1"  # type: ignore[index]
        assert ctx["rows"] == 42  # type: ignore[index]

    def test_outcome_failure(self) -> None:
        buf = io.StringIO()
        extra = self._record(buf, outcome="failure")["record"]["extra"]  # type: ignore[index]
        assert extra["outcome"] == "failure"  # type: ignore[index]

    def test_resource_id(self) -> None:
        buf = io.StringIO()
        extra = self._record(buf, resource_id="doc-42")["record"]["extra"]  # type: ignore[index]
        assert extra["resource_id"] == "doc-42"  # type: ignore[index]

    def test_sequence_increases_across_events(self) -> None:
        buf = io.StringIO()
        stream = _loguru_stream(buf)
        stream.record("a", principal=_PRINCIPAL, resource="r")
        stream.record("b", principal=_PRINCIPAL, resource="r")
        lines = buf.getvalue().strip().splitlines()
        seqs = [json.loads(line)["record"]["extra"]["sequence"] for line in lines]
        assert seqs == [1, 2]

    def test_checksum_present_and_64_chars(self) -> None:
        buf = io.StringIO()
        extra = self._record(buf)["record"]["extra"]  # type: ignore[index]
        assert len(extra["checksum"]) == 64  # type: ignore[index]

    def test_timestamp_is_iso8601(self) -> None:
        from datetime import datetime

        buf = io.StringIO()
        extra = self._record(buf)["record"]["extra"]  # type: ignore[index]
        ts = datetime.fromisoformat(extra["timestamp"])  # type: ignore[arg-type]
        assert ts.tzinfo is not None

    def test_custom_sink(self) -> None:
        """LoguruAuditStream forwards sink_kwargs to loguru.add."""
        buf = io.StringIO()
        stream = LoguruAuditStream(sink=buf, level="DEBUG")
        event = stream.record("read", principal=_PRINCIPAL, resource="file")
        assert event.sequence == 1
        assert buf.getvalue()  # non-empty
