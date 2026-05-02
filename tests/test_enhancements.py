"""Tests for all new airlog enhancements.

Covers:
- HealthStatus / StreamFeature / health_check() / supports_feature() / aemit()
- AuditEvent.to_dict() / to_ocsf()
- AuditPipeline / middleware (Redaction, Enrichment)
- LoggingAdapter / OpenTelemetryAdapter
- Registry (register, deregister, list_backends, emit, aemit)
- BackendComplianceTest base class
- OCSF support (OcsfClass, OcsfSeverity, detect_ocsf_class, build_ocsf_event,
  validate_ocsf_event, OcsfStream)
"""

from __future__ import annotations

import asyncio
import io
import json
import logging
import re
import threading

import pytest

import airlog.registry as registry
from airlog import (
    AuditEvent,
    AuditPipeline,
    AuditStream,
    EnrichmentMiddleware,
    HealthStatus,
    LoggingAdapter,
    OcsfClass,
    OcsfSeverity,
    OcsfStream,
    Principal,
    RedactionMiddleware,
    SerializationFormat,
    StreamFeature,
)
from airlog.ocsf_support import build_ocsf_event, detect_ocsf_class, validate_ocsf_event
from airlog.testing import BackendComplianceTest

_P = Principal(subject="test-user", auth_method="jwt")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _CapturingStream(AuditStream):
    """Minimal in-memory AuditStream for testing."""

    def __init__(self) -> None:
        super().__init__()
        self.events: list[AuditEvent] = []

    def emit(self, event: AuditEvent) -> None:
        self.events.append(event)


def _event(stream: AuditStream | None = None, **overrides: object) -> AuditEvent:
    s = stream or _CapturingStream()
    return s.record(  # type: ignore[return-value]
        action=overrides.pop("action", "test_action"),  # type: ignore[arg-type]
        principal=overrides.pop("principal", _P),  # type: ignore[arg-type]
        resource=overrides.pop("resource", "test_resource"),  # type: ignore[arg-type]
        **overrides,  # type: ignore[arg-type]
    )


# ===========================================================================
# StreamFeature
# ===========================================================================


class TestStreamFeature:
    def test_all_members_exist(self) -> None:
        members = {f.name for f in StreamFeature}
        assert members == {"QUERY", "REPLAY", "RETENTION", "BATCHING", "ASYNC"}

    def test_supports_feature_default_false(self) -> None:
        stream = _CapturingStream()
        for feature in StreamFeature:
            assert stream.supports_feature(feature) is False


# ===========================================================================
# HealthStatus
# ===========================================================================


class TestHealthStatus:
    def test_healthy_fields(self) -> None:
        hs = HealthStatus(healthy=True, latency_ms=1.5)
        assert hs.healthy is True
        assert hs.latency_ms == 1.5
        assert hs.message == ""

    def test_unhealthy_with_message(self) -> None:
        hs = HealthStatus(healthy=False, latency_ms=0.0, message="connection refused")
        assert hs.healthy is False
        assert hs.message == "connection refused"

    def test_health_check_default_returns_healthy(self) -> None:
        stream = _CapturingStream()
        status = stream.health_check()
        assert isinstance(status, HealthStatus)
        assert status.healthy is True
        assert status.latency_ms >= 0.0
        assert isinstance(status.message, str)


# ===========================================================================
# AuditEvent.to_dict
# ===========================================================================


class TestToDict:
    def test_json_returns_dict(self) -> None:
        ev = _event()
        result = ev.to_dict(SerializationFormat.JSON)
        assert isinstance(result, dict)

    def test_json_default_format(self) -> None:
        ev = _event()
        assert ev.to_dict() == ev.to_dict(SerializationFormat.JSON)

    def test_json_contains_all_fields(self) -> None:
        ev = _event()
        d = ev.to_dict()  # type: ignore[assignment]
        for field_name in (
            "event_id",
            "sequence",
            "timestamp_ns",
            "action",
            "principal",
            "resource",
            "resource_id",
            "outcome",
            "correlation_id",
            "context",
            "checksum",
        ):
            assert field_name in d, f"Missing field: {field_name}"

    def test_json_principal_sub_dict(self) -> None:
        ev = _event()
        d = ev.to_dict()  # type: ignore[assignment]
        assert d["principal"]["subject"] == _P.subject  # type: ignore[index]
        assert d["principal"]["auth_method"] == _P.auth_method  # type: ignore[index]

    def test_json_round_trip_verify(self) -> None:
        import json

        ev = _event()
        raw = json.dumps(ev.to_dict())
        data = json.loads(raw)
        reconstructed = AuditEvent(
            event_id=data["event_id"],
            sequence=data["sequence"],
            timestamp_ns=data["timestamp_ns"],
            action=data["action"],
            principal=Principal(
                subject=data["principal"]["subject"],
                auth_method=data["principal"]["auth_method"],
                metadata=data["principal"]["metadata"],
            ),
            resource=data["resource"],
            resource_id=data["resource_id"],
            outcome=data["outcome"],
            correlation_id=data["correlation_id"],
            context=data["context"],
            checksum=data["checksum"],
        )
        assert reconstructed.verify()

    def test_msgpack_returns_bytes(self) -> None:
        pytest.importorskip("msgpack")
        ev = _event()
        result = ev.to_dict(SerializationFormat.MSGPACK)
        assert isinstance(result, bytes)

    def test_msgpack_missing_raises_import_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import builtins

        real_import = builtins.__import__

        def _block_msgpack(name: str, *args: object, **kwargs: object) -> object:
            if name == "msgpack":
                raise ImportError("no module named msgpack")
            return real_import(name, *args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(builtins, "__import__", _block_msgpack)
        ev = _event()
        with pytest.raises(ImportError, match="msgpack"):
            ev.to_dict(SerializationFormat.MSGPACK)


# ===========================================================================
# AuditEvent.to_ocsf
# ===========================================================================


class TestToOcsf:
    def test_returns_dict(self) -> None:
        assert isinstance(_event().to_ocsf(), dict)

    def test_class_uid(self) -> None:
        assert _event().to_ocsf()["class_uid"] == 6003

    def test_success_status(self) -> None:
        ev = _event(outcome="success")
        ocsf = ev.to_ocsf()
        assert ocsf["status"] == "success"
        assert ocsf["status_id"] == 1

    def test_failure_status(self) -> None:
        ev = _event(outcome="failure")
        ocsf = ev.to_ocsf()
        assert ocsf["status"] == "failure"
        assert ocsf["status_id"] == 2

    def test_actor_mapping(self) -> None:
        ev = _event()
        actor = ev.to_ocsf()["actor"]
        assert actor["user"]["name"] == _P.subject
        assert actor["idp"]["name"] == _P.auth_method

    def test_metadata_uid_is_event_id(self) -> None:
        ev = _event()
        assert ev.to_ocsf()["metadata"]["uid"] == ev.event_id

    def test_resource_mapping(self) -> None:
        ev = _event(resource="document", resource_id="doc-42")
        resources = ev.to_ocsf()["resources"]
        assert resources[0]["type"] == "document"
        assert resources[0]["uid"] == "doc-42"


# ===========================================================================
# aemit
# ===========================================================================


class TestAemit:
    def test_aemit_returns_true(self) -> None:
        stream = _CapturingStream()
        ev = _event(stream)
        result = asyncio.run(stream.aemit(ev))
        assert result is True

    def test_aemit_calls_emit(self) -> None:
        stream = _CapturingStream()
        ev = _event()
        asyncio.run(stream.aemit(ev))
        assert ev in stream.events

    def test_aemit_is_awaitable(self) -> None:
        stream = _CapturingStream()
        ev = _event()
        coro = stream.aemit(ev)
        assert asyncio.iscoroutine(coro)
        asyncio.run(coro)


# ===========================================================================
# Middleware / AuditPipeline
# ===========================================================================


class TestRedactionMiddleware:
    def test_redacts_email(self) -> None:
        mw = RedactionMiddleware()
        stream = _CapturingStream()
        ev = _event(stream, email="user@example.com")
        result = mw.process(ev)
        assert result is not None
        assert "user@example.com" not in result.context.get("email", "")
        assert "[REDACTED-EMAIL]" in result.context.get("email", "")

    def test_redacts_ssn(self) -> None:
        mw = RedactionMiddleware()
        stream = _CapturingStream()
        ev = _event(stream, ssn="123-45-6789")
        result = mw.process(ev)
        assert result is not None
        assert "123-45-6789" not in result.context.get("ssn", "")
        assert "[REDACTED-SSN]" in result.context.get("ssn", "")

    def test_unchanged_event_returned_as_is(self) -> None:
        mw = RedactionMiddleware()
        ev = _event()
        result = mw.process(ev)
        assert result is ev  # same object - no copy

    def test_redacted_event_passes_verify(self) -> None:
        mw = RedactionMiddleware()
        ev = _event(email="user@example.com")
        result = mw.process(ev)
        assert result is not None
        assert result.verify()

    def test_custom_patterns(self) -> None:
        patterns = [(re.compile(r"\d+"), "[NUM]")]
        mw = RedactionMiddleware(patterns=patterns)
        ev = _event(ip="192.168.1.1")
        result = mw.process(ev)
        assert result is not None
        assert result.context["ip"] == "[NUM].[NUM].[NUM].[NUM]"

    def test_non_string_values_unchanged(self) -> None:
        mw = RedactionMiddleware()
        ev = _event(count=42)
        result = mw.process(ev)
        assert result is not None
        assert result.context["count"] == 42  # type: ignore[comparison-overlap]


class TestEnrichmentMiddleware:
    def test_injects_fields(self) -> None:
        mw = EnrichmentMiddleware(env="prod", region="us-east-1")
        ev = _event()
        result = mw.process(ev)
        assert result is not None
        assert result.context["env"] == "prod"
        assert result.context["region"] == "us-east-1"

    def test_does_not_overwrite_existing(self) -> None:
        stream = _CapturingStream()
        ev = stream.record("op", principal=_P, resource="r", env="existing")
        mw = EnrichmentMiddleware(env="injected")
        result = mw.process(ev)
        assert result is not None
        assert result.context["env"] == "existing"

    def test_no_extra_fields_returns_same(self) -> None:
        ev = _event(env="prod")
        mw = EnrichmentMiddleware(env="prod")
        # All keys already present - no change expected (env already in context)
        result = mw.process(ev)
        assert result is ev

    def test_enriched_event_passes_verify(self) -> None:
        mw = EnrichmentMiddleware(env="prod")
        ev = _event()
        result = mw.process(ev)
        assert result is not None
        assert result.verify()


class TestAuditPipeline:
    def test_emit_forwards_to_streams(self) -> None:
        backend = _CapturingStream()
        pipeline = AuditPipeline(backend)
        ev = _event()
        pipeline.emit(ev)
        assert ev in backend.events

    def test_record_via_pipeline(self) -> None:
        backend = _CapturingStream()
        pipeline = AuditPipeline(backend)
        ev = pipeline.record("login", principal=_P, resource="session")
        assert ev in backend.events
        assert ev.verify()

    def test_middleware_applied(self) -> None:
        backend = _CapturingStream()
        pipeline = AuditPipeline(backend).add(EnrichmentMiddleware(env="test"))
        pipeline.record("op", principal=_P, resource="r")
        assert backend.events[0].context["env"] == "test"

    def test_chaining_returns_pipeline(self) -> None:
        pipeline = AuditPipeline(_CapturingStream())
        result = pipeline.add(RedactionMiddleware())
        assert result is pipeline

    def test_middleware_drop(self) -> None:
        class _Dropper:
            def process(self, event: AuditEvent) -> AuditEvent | None:
                return None

        backend = _CapturingStream()
        pipeline = AuditPipeline(backend).add(_Dropper())
        pipeline.record("op", principal=_P, resource="r")
        assert len(backend.events) == 0

    def test_multiple_backends(self) -> None:
        b1, b2 = _CapturingStream(), _CapturingStream()
        pipeline = AuditPipeline(b1, b2)
        pipeline.record("op", principal=_P, resource="r")
        assert len(b1.events) == 1
        assert len(b2.events) == 1

    def test_health_check_all_healthy(self) -> None:
        pipeline = AuditPipeline(_CapturingStream(), _CapturingStream())
        status = pipeline.health_check()
        assert status.healthy is True

    def test_health_check_no_backends(self) -> None:
        pipeline = AuditPipeline()
        status = pipeline.health_check()
        assert status.healthy is True

    def test_supports_feature_any_backend(self) -> None:
        class _AsyncStream(_CapturingStream):
            def supports_feature(self, feature: StreamFeature) -> bool:
                return feature == StreamFeature.ASYNC

        pipeline = AuditPipeline(_CapturingStream(), _AsyncStream())
        assert pipeline.supports_feature(StreamFeature.ASYNC) is True
        assert pipeline.supports_feature(StreamFeature.QUERY) is False

    def test_aemit_through_pipeline(self) -> None:
        backend = _CapturingStream()
        pipeline = AuditPipeline(backend)
        ev = _event()

        result = asyncio.run(pipeline.aemit(ev))
        assert result is True
        assert ev in backend.events

    def test_aemit_drop_returns_false(self) -> None:
        class _Dropper:
            def process(self, event: AuditEvent) -> AuditEvent | None:
                return None

        pipeline = AuditPipeline(_CapturingStream()).add(_Dropper())
        ev = _event()
        result = asyncio.run(pipeline.aemit(ev))
        assert result is False


# ===========================================================================
# LoggingAdapter
# ===========================================================================


class TestLoggingAdapter:
    def _make_adapter(self) -> tuple[LoggingAdapter, list[logging.LogRecord]]:
        records: list[logging.LogRecord] = []

        class _Handler(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                records.append(record)

        log = logging.getLogger(f"test_airlog.{id(self)}")
        log.addHandler(_Handler())
        log.setLevel(logging.DEBUG)
        return LoggingAdapter(logger=log), records

    def test_emit_produces_log_record(self) -> None:
        adapter, records = self._make_adapter()
        ev = _event()
        adapter.emit(ev)
        assert len(records) == 1

    def test_record_fields_in_extra(self) -> None:
        adapter, records = self._make_adapter()
        ev = _event()
        adapter.emit(ev)
        record = records[0]
        assert record.audit_event_id == ev.event_id  # type: ignore[attr-defined]
        assert record.audit_action == ev.action  # type: ignore[attr-defined]
        assert record.audit_outcome == ev.outcome  # type: ignore[attr-defined]

    def test_default_level_is_info(self) -> None:
        adapter, records = self._make_adapter()
        ev = _event()
        adapter.emit(ev)
        assert records[0].levelno == logging.INFO

    def test_custom_level(self) -> None:
        records: list[logging.LogRecord] = []

        class _Handler(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                records.append(record)

        log = logging.getLogger(f"test_airlog.custom.{id(self)}")
        log.addHandler(_Handler())
        log.setLevel(logging.DEBUG)
        adapter = LoggingAdapter(logger=log, level=logging.WARNING)
        adapter.emit(_event())
        assert records[0].levelno == logging.WARNING

    def test_health_check_with_handler(self) -> None:
        adapter, _ = self._make_adapter()
        status = adapter.health_check()
        assert status.healthy is True

    def test_health_check_no_handler(self) -> None:
        bare_log = logging.getLogger(f"test_airlog.bare.{id(self)}")
        # Ensure no handlers and no propagation to root
        bare_log.handlers = []
        bare_log.propagate = False
        adapter = LoggingAdapter(logger=bare_log)
        status = adapter.health_check()
        assert status.healthy is False

    def test_supports_feature_all_false(self) -> None:
        adapter, _ = self._make_adapter()
        for feature in StreamFeature:
            assert adapter.supports_feature(feature) is False

    def test_stream_record_calls_emit(self) -> None:
        adapter, records = self._make_adapter()
        adapter.record("login", principal=_P, resource="session")
        assert len(records) == 1


# ===========================================================================
# OpenTelemetryAdapter
# ===========================================================================


class TestOpenTelemetryAdapter:
    def test_raises_import_error_without_otel(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import builtins

        real_import = builtins.__import__

        def _block_otel(name: str, *args: object, **kwargs: object) -> object:
            if name.startswith("opentelemetry"):
                raise ImportError("no module named opentelemetry")
            return real_import(name, *args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(builtins, "__import__", _block_otel)

        from airlog.adapters.opentelemetry_adapter import OpenTelemetryAdapter as _Adapter

        with pytest.raises(ImportError, match="opentelemetry-api"):
            _Adapter()

    def test_supports_async_feature(self) -> None:
        pytest.importorskip("opentelemetry")
        from airlog.adapters import OpenTelemetryAdapter

        adapter = OpenTelemetryAdapter()
        assert adapter.supports_feature(StreamFeature.ASYNC) is True
        assert adapter.supports_feature(StreamFeature.QUERY) is False

    def test_health_check_with_otel(self) -> None:
        pytest.importorskip("opentelemetry")
        from airlog.adapters import OpenTelemetryAdapter

        adapter = OpenTelemetryAdapter()
        status = adapter.health_check()
        assert status.healthy is True

    def test_aemit_is_sync_and_returns_true(self) -> None:
        pytest.importorskip("opentelemetry")
        from airlog.adapters import OpenTelemetryAdapter

        adapter = OpenTelemetryAdapter()
        ev = _event()
        result = asyncio.run(adapter.aemit(ev))
        assert result is True


# ===========================================================================
# Registry
# ===========================================================================


class TestRegistry:
    def setup_method(self) -> None:
        # Clear registry state before each test
        for name in list(registry.list_backends()):
            registry.deregister(name)

    def test_register_and_list(self) -> None:
        stream = _CapturingStream()
        registry.register("test", stream)
        assert "test" in registry.list_backends()

    def test_list_returns_snapshot(self) -> None:
        stream = _CapturingStream()
        registry.register("snap", stream)
        snapshot = registry.list_backends()
        registry.deregister("snap")
        assert "snap" in snapshot  # snapshot not affected

    def test_deregister_removes(self) -> None:
        registry.register("temp", _CapturingStream())
        registry.deregister("temp")
        assert "temp" not in registry.list_backends()

    def test_deregister_missing_raises_key_error(self) -> None:
        with pytest.raises(KeyError):
            registry.deregister("nonexistent")

    def test_emit_all_backends(self) -> None:
        a, b = _CapturingStream(), _CapturingStream()
        registry.register("a", a)
        registry.register("b", b)
        ev = _event()
        results = registry.emit(ev)
        assert results == {"a": True, "b": True}
        assert ev in a.events
        assert ev in b.events

    def test_emit_named_subset(self) -> None:
        a, b = _CapturingStream(), _CapturingStream()
        registry.register("a", a)
        registry.register("b", b)
        ev = _event()
        results = registry.emit(ev, backends=["a"])
        assert "a" in results
        assert "b" not in results
        assert ev in a.events
        assert ev not in b.events

    def test_emit_predicate(self) -> None:
        a, b = _CapturingStream(), _CapturingStream()
        registry.register("primary", a)
        registry.register("secondary", b)
        ev = _event()
        results = registry.emit(ev, backends=lambda n, _: n.startswith("primary"))
        assert "primary" in results
        assert "secondary" not in results

    def test_emit_error_is_caught(self) -> None:
        class _FailStream(AuditStream):
            def emit(self, event: AuditEvent) -> None:
                raise RuntimeError("storage unavailable")

        registry.register("failing", _FailStream())
        ev = _event()
        results = registry.emit(ev)
        assert results["failing"] is False

    def test_aemit_all_backends(self) -> None:
        a, b = _CapturingStream(), _CapturingStream()
        registry.register("a", a)
        registry.register("b", b)
        ev = _event()
        results = asyncio.run(registry.aemit(ev))
        assert results == {"a": True, "b": True}

    def test_aemit_named_subset(self) -> None:
        a, b = _CapturingStream(), _CapturingStream()
        registry.register("a", a)
        registry.register("b", b)
        ev = _event()
        results = asyncio.run(registry.aemit(ev, backends=["b"]))
        assert "b" in results
        assert "a" not in results

    def test_thread_safe_register(self) -> None:
        n = 20
        streams = [_CapturingStream() for _ in range(n)]
        threads = [
            threading.Thread(target=registry.register, args=(f"t{i}", streams[i])) for i in range(n)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        backends = registry.list_backends()
        assert all(f"t{i}" in backends for i in range(n))


# ===========================================================================
# BackendComplianceTest base class - verified with _CapturingStream
# ===========================================================================


class TestBackendComplianceConcreteImpl(BackendComplianceTest):
    """Run the full compliance suite against the in-memory _CapturingStream."""

    @pytest.fixture
    def stream(self) -> _CapturingStream:
        return _CapturingStream()


# ===========================================================================
# OcsfClass / OcsfSeverity enums
# ===========================================================================


class TestOcsfEnums:
    def test_ocsf_class_values(self) -> None:
        assert int(OcsfClass.ACCOUNT_CHANGE) == 3001
        assert int(OcsfClass.AUTHENTICATION) == 3002
        assert int(OcsfClass.ENTITY_MANAGEMENT) == 3004
        assert int(OcsfClass.API_ACTIVITY) == 6003

    def test_ocsf_severity_values(self) -> None:
        assert int(OcsfSeverity.UNKNOWN) == 0
        assert int(OcsfSeverity.INFORMATIONAL) == 1
        assert int(OcsfSeverity.LOW) == 2
        assert int(OcsfSeverity.MEDIUM) == 3
        assert int(OcsfSeverity.HIGH) == 4
        assert int(OcsfSeverity.CRITICAL) == 5
        assert int(OcsfSeverity.OTHER) == 99


# ===========================================================================
# detect_ocsf_class
# ===========================================================================


class TestDetectOcsfClass:
    def test_auth_actions_map_to_authentication(self) -> None:
        for action in ("login", "logout", "logon", "logoff", "signin", "sign_in", "mfa", "sso"):
            assert detect_ocsf_class(action) == OcsfClass.AUTHENTICATION, action

    def test_account_actions_map_to_account_change(self) -> None:
        for action in ("create_user", "delete_user", "reset_password", "lock_user"):
            assert detect_ocsf_class(action) == OcsfClass.ACCOUNT_CHANGE, action

    def test_generic_action_defaults_to_api_activity(self) -> None:
        for action in ("create", "read", "update", "delete", "export", "import"):
            assert detect_ocsf_class(action) == OcsfClass.API_ACTIVITY, action

    def test_case_insensitive(self) -> None:
        assert detect_ocsf_class("LOGIN") == OcsfClass.AUTHENTICATION
        assert detect_ocsf_class("CREATE_USER") == OcsfClass.ACCOUNT_CHANGE

    def test_unknown_action_defaults_to_api_activity(self) -> None:
        assert detect_ocsf_class("frobnicate") == OcsfClass.API_ACTIVITY


# ===========================================================================
# build_ocsf_event
# ===========================================================================


class TestBuildOcsfEvent:
    def _event(self, action: str = "create", **kw: object) -> AuditEvent:
        stream = _CapturingStream()
        return stream.record(
            action,
            principal=_P,
            resource=kw.pop("resource", "document"),  # type: ignore[arg-type]
            resource_id=kw.pop("resource_id", "doc-1"),  # type: ignore[arg-type]
            outcome=kw.pop("outcome", "success"),  # type: ignore[arg-type]
            **kw,  # type: ignore[arg-type]
        )

    # --- API Activity (default) ---

    def test_api_activity_class_uid(self) -> None:
        ev = self._event("create")
        result = build_ocsf_event(ev)
        assert result["class_uid"] == 6003
        assert result["class_name"] == "API Activity"
        assert result["category_uid"] == 6

    def test_api_activity_has_actor_user(self) -> None:
        ev = self._event()
        result = build_ocsf_event(ev)
        assert result["actor"]["user"]["name"] == _P.subject
        assert result["actor"]["idp"]["name"] == _P.auth_method

    def test_api_activity_has_api_field(self) -> None:
        ev = self._event("update")
        result = build_ocsf_event(ev)
        assert result["api"]["operation"] == "update"

    def test_api_activity_activity_id_create(self) -> None:
        assert build_ocsf_event(self._event("create"))["activity_id"] == 1

    def test_api_activity_activity_id_read(self) -> None:
        assert build_ocsf_event(self._event("get"))["activity_id"] == 2

    def test_api_activity_activity_id_update(self) -> None:
        assert build_ocsf_event(self._event("update"))["activity_id"] == 3

    def test_api_activity_activity_id_delete(self) -> None:
        assert build_ocsf_event(self._event("delete"))["activity_id"] == 4

    def test_api_activity_activity_id_unknown_is_99(self) -> None:
        assert build_ocsf_event(self._event("frobnicate"))["activity_id"] == 99

    # --- Authentication ---

    def test_authentication_class_uid(self) -> None:
        ev = self._event("login")
        result = build_ocsf_event(ev, ocsf_class=OcsfClass.AUTHENTICATION)
        assert result["class_uid"] == 3002
        assert result["class_name"] == "Authentication"
        assert result["category_uid"] == 3

    def test_authentication_auto_detect(self) -> None:
        ev = self._event("login")
        assert build_ocsf_event(ev)["class_uid"] == 3002

    def test_authentication_has_user_field(self) -> None:
        ev = self._event("login")
        result = build_ocsf_event(ev)
        assert result["user"]["name"] == _P.subject

    def test_authentication_activity_id_logon(self) -> None:
        ev = self._event("login")
        assert build_ocsf_event(ev)["activity_id"] == 1

    def test_authentication_activity_id_logoff(self) -> None:
        ev = self._event("logout")
        assert build_ocsf_event(ev)["activity_id"] == 2

    # --- Account Change ---

    def test_account_change_class_uid(self) -> None:
        ev = self._event("create_user")
        result = build_ocsf_event(ev)
        assert result["class_uid"] == 3001
        assert result["class_name"] == "Account Change"

    def test_account_change_has_user_field(self) -> None:
        ev = self._event("create_user")
        assert build_ocsf_event(ev)["user"]["name"] == _P.subject

    def test_account_change_activity_id_create(self) -> None:
        ev = self._event("create_user")
        assert build_ocsf_event(ev)["activity_id"] == 1

    def test_account_change_activity_id_reset_password(self) -> None:
        ev = self._event("reset_password")
        assert build_ocsf_event(ev)["activity_id"] == 4

    def test_account_change_activity_id_lock(self) -> None:
        ev = self._event("lock_user")
        assert build_ocsf_event(ev)["activity_id"] == 9

    # --- Common fields ---

    def test_severity_id_defaults_to_informational(self) -> None:
        ev = self._event()
        assert build_ocsf_event(ev)["severity_id"] == 1
        assert build_ocsf_event(ev)["severity"] == "Informational"

    def test_severity_id_override(self) -> None:
        ev = self._event()
        result = build_ocsf_event(ev, severity_id=OcsfSeverity.HIGH)
        assert result["severity_id"] == 4
        assert result["severity"] == "High"

    def test_success_status(self) -> None:
        ev = self._event(outcome="success")
        result = build_ocsf_event(ev)
        assert result["status"] == "success"
        assert result["status_id"] == 1

    def test_failure_status(self) -> None:
        ev = self._event(outcome="failure")
        result = build_ocsf_event(ev)
        assert result["status"] == "failure"
        assert result["status_id"] == 2

    def test_metadata_uid_is_event_id(self) -> None:
        ev = self._event()
        assert build_ocsf_event(ev)["metadata"]["uid"] == ev.event_id

    def test_metadata_version(self) -> None:
        ev = self._event()
        assert build_ocsf_event(ev)["metadata"]["version"] == "1.1.0"

    def test_resources_mapping(self) -> None:
        ev = self._event(resource="document", resource_id="doc-42")
        resources = build_ocsf_event(ev)["resources"]
        assert resources[0]["type"] == "document"
        assert resources[0]["uid"] == "doc-42"

    def test_time_is_milliseconds(self) -> None:
        ev = self._event()
        result = build_ocsf_event(ev)
        assert result["time"] == ev.timestamp_ns // 1_000_000

    def test_explicit_ocsf_class_overrides_detection(self) -> None:
        ev = self._event("login")  # would normally → AUTHENTICATION
        result = build_ocsf_event(ev, ocsf_class=OcsfClass.API_ACTIVITY)
        assert result["class_uid"] == 6003


# ===========================================================================
# validate_ocsf_event  (requires ocsf-lib - available in dev deps)
# ===========================================================================


class TestValidateOcsfEvent:
    def _valid_event(self) -> AuditEvent:
        stream = _CapturingStream()
        return stream.record("create", principal=_P, resource="doc", resource_id="d1")

    def test_valid_event_returns_no_errors(self) -> None:
        ev = self._valid_event()
        errors = validate_ocsf_event(build_ocsf_event(ev))
        assert errors == []

    def test_missing_required_field_returns_error(self) -> None:
        ev = self._valid_event()
        ocsf = build_ocsf_event(ev)
        del ocsf["time"]  # 'time' is required in OCSF
        errors = validate_ocsf_event(ocsf)
        assert any("time" in e for e in errors)

    def test_unknown_class_uid_returns_error(self) -> None:
        errors = validate_ocsf_event({"class_uid": 9999})
        assert errors and "9999" in errors[0]


# ===========================================================================
# OcsfStream adapter
# ===========================================================================


class TestOcsfStream:
    def _make_stream(self, **kw: object) -> tuple[OcsfStream, io.StringIO]:
        buf = io.StringIO()
        stream = OcsfStream(sink=buf, **kw)  # type: ignore[arg-type]
        return stream, buf

    def _record(
        self, stream: OcsfStream, action: str = "create", **kw: object
    ) -> dict[str, object]:
        buf_stream = stream._sink  # type: ignore[attr-defined]
        pos = buf_stream.tell()
        stream.record(
            action,
            principal=_P,
            resource=kw.pop("resource", "document"),  # type: ignore[arg-type]
            **kw,  # type: ignore[arg-type]
        )
        buf_stream.seek(pos)
        return json.loads(buf_stream.read().strip())

    def test_emits_valid_json(self) -> None:
        stream, buf = self._make_stream()
        stream.record("create", principal=_P, resource="doc")
        result = json.loads(buf.getvalue().strip())
        assert "class_uid" in result

    def test_default_class_is_api_activity(self) -> None:
        stream, _ = self._make_stream()
        result = self._record(stream, "create")
        assert result["class_uid"] == 6003

    def test_login_auto_detects_authentication(self) -> None:
        stream, _ = self._make_stream()
        result = self._record(stream, "login")
        assert result["class_uid"] == 3002

    def test_explicit_ocsf_class(self) -> None:
        stream, _ = self._make_stream(ocsf_class=OcsfClass.ACCOUNT_CHANGE)
        result = self._record(stream, "login")
        assert result["class_uid"] == 3001

    def test_severity_id_propagated(self) -> None:
        stream, _ = self._make_stream(severity_id=OcsfSeverity.HIGH)
        result = self._record(stream)
        assert result["severity_id"] == 4

    def test_each_event_is_one_line(self) -> None:
        stream, buf = self._make_stream()
        for _ in range(3):
            stream.record("create", principal=_P, resource="doc")
        lines = [ln for ln in buf.getvalue().splitlines() if ln.strip()]
        assert len(lines) == 3

    def test_health_check_healthy(self) -> None:
        stream, _ = self._make_stream()
        assert stream.health_check().healthy is True

    def test_health_check_unhealthy_sink(self) -> None:
        # A closed StringIO is not writable
        buf = io.StringIO()
        buf.close()
        stream = OcsfStream(sink=buf)
        status = stream.health_check()
        assert status.healthy is False
        assert status.message != ""

    def test_supports_feature_returns_false(self) -> None:
        stream, _ = self._make_stream()
        for feature in StreamFeature:
            assert stream.supports_feature(feature) is False

    def test_validate_emits_warning_for_missing_field(self) -> None:
        import warnings

        buf = io.StringIO()
        stream = OcsfStream(sink=buf, validate=True)
        # Monkeypatch validate_ocsf_event to return an error
        import airlog.adapters.ocsf_adapter as _mod

        original = _mod.validate_ocsf_event

        def _fake_validate(d: object, schema_version: str = "") -> list[str]:
            return ["Missing required field 'time'"]

        _mod.validate_ocsf_event = _fake_validate
        try:
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                stream.record("create", principal=_P, resource="doc")
            assert any("OCSF validation" in str(w.message) for w in caught)
        finally:
            _mod.validate_ocsf_event = original

    def test_validate_raises_without_ocsf_lib(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import builtins

        real_import = builtins.__import__

        def mock_import(name: str, *args: object, **kwargs: object) -> object:
            if name == "ocsf.util":
                raise ImportError("mocked missing ocsf-lib")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)
        with pytest.raises(ImportError, match="ocsf-lib"):
            OcsfStream(validate=True)


# ===========================================================================
# Extra coverage gaps
# ===========================================================================


class TestStreamsModule:
    """Ensure airlog.streams re-exports are importable (covers streams.py)."""

    def test_imports(self) -> None:
        from airlog.streams import (  # noqa: F401
            AuditEvent,
            AuditStream,
            HealthStatus,
            Principal,
            SerializationFormat,
            StreamFeature,
        )


class TestInterfacesMiscCoverage:
    def test_health_check_exception_branch(self) -> None:
        """AuditStream.health_check() exception branch."""

        class _BrokenLockStream(AuditStream):
            def __init__(self) -> None:
                super().__init__()
                # Replace the lock with a mock that raises on acquire
                self._lock = None  # type: ignore[assignment]

            def emit(self, event: AuditEvent) -> None:
                pass

        stream = _BrokenLockStream()
        status = stream.health_check()
        assert status.healthy is False

    def test_msgpack_import_error(self) -> None:
        import builtins

        real_import = builtins.__import__
        ev = _CapturingStream().record("x", principal=_P, resource="r")

        def mock_import(name: str, *args: object, **kwargs: object) -> object:
            if name == "msgpack":
                raise ImportError("no msgpack")
            return real_import(name, *args, **kwargs)

        import builtins as _bi

        _bi.__import__ = mock_import
        try:
            with pytest.raises(ImportError, match="msgpack"):
                ev.to_dict(SerializationFormat.MSGPACK)
        finally:
            _bi.__import__ = real_import


class TestLoggingAdapterCoverage:
    def test_health_check_no_handlers(self) -> None:
        """LoggingAdapter.health_check() returns unhealthy when no handlers."""
        isolated = logging.getLogger("airlog.test.no_handlers_xyz")
        # Ensure no handlers and propagation is disabled
        isolated.handlers = []
        isolated.propagate = False
        adapter = LoggingAdapter(logger=isolated)
        status = adapter.health_check()
        assert status.healthy is False
        assert "no handlers" in status.message


class TestMiddlewareCoverage:
    def test_pipeline_health_check_unhealthy_backend(self) -> None:
        class _UnhealthyStream(AuditStream):
            def emit(self, event: AuditEvent) -> None:
                pass

            def health_check(self) -> HealthStatus:
                return HealthStatus(healthy=False, latency_ms=1.0, message="broken")

        pipeline = AuditPipeline(_UnhealthyStream())
        status = pipeline.health_check()
        assert status.healthy is False
        assert "broken" in status.message


class TestRegistryCoverage:
    def setup_method(self) -> None:
        for name in list(registry.list_backends()):
            registry.deregister(name)

    def test_emit_sync_or_async_sync_path(self) -> None:
        from airlog.registry import emit_sync_or_async

        stream = _CapturingStream()
        registry.register("s", stream)
        ev = stream.record("x", principal=_P, resource="r")
        result = emit_sync_or_async(ev)
        assert isinstance(result, dict)
        assert "s" in result

    def test_emit_sync_or_async_async_path(self) -> None:
        from airlog.registry import emit_sync_or_async

        stream = _CapturingStream()
        registry.register("s", stream)
        ev = stream.record("x", principal=_P, resource="r")

        async def _run() -> object:
            return await emit_sync_or_async(ev)

        result = asyncio.run(_run())
        assert isinstance(result, dict)

    def test_select_backends_unknown_type_returns_empty(self) -> None:
        """_select_backends with an unsupported type returns []."""
        from airlog.registry import _select_backends

        stream = _CapturingStream()
        registry.register("x", stream)
        snapshot = list(registry.list_backends().items())
        result = _select_backends(42, snapshot)  # type: ignore[arg-type]
        assert result == []

    def test_aemit_exception_caught(self) -> None:
        class _FailAsync(AuditStream):
            def emit(self, event: AuditEvent) -> None:
                pass

            async def aemit(self, event: AuditEvent) -> bool:
                raise RuntimeError("async fail")

        registry.register("fa", _FailAsync())
        stream = _CapturingStream()
        registry.register("ok", stream)
        ev = stream.record("x", principal=_P, resource="r")
        result = asyncio.run(registry.aemit(ev))
        assert result["fa"] is False
        assert result["ok"] is True


class TestOcsfSupportCoverage:
    def _event(self, action: str = "create") -> AuditEvent:
        return _CapturingStream().record(action, principal=_P, resource="role", resource_id="r-1")

    def test_entity_management_class(self) -> None:
        ev = self._event("update")
        result = build_ocsf_event(ev, ocsf_class=OcsfClass.ENTITY_MANAGEMENT)
        assert result["class_uid"] == 3004
        assert "entity" in result
        assert result["entity"]["type"] == "role"

    def test_entity_management_activity_id(self) -> None:
        ev = self._event("delete")
        result = build_ocsf_event(ev, ocsf_class=OcsfClass.ENTITY_MANAGEMENT)
        assert result["activity_id"] == 4

    def test_entity_management_unknown_activity_is_99(self) -> None:
        ev = self._event("frobnicate")
        result = build_ocsf_event(ev, ocsf_class=OcsfClass.ENTITY_MANAGEMENT)
        assert result["activity_id"] == 99

    def test_validate_uses_cached_schema(self) -> None:
        from airlog.ocsf_support import _schema_cache

        ev = self._event()
        ocsf = build_ocsf_event(ev)
        # First call populates cache; second call should use it
        validate_ocsf_event(ocsf)
        validate_ocsf_event(ocsf)
        assert "1.1.0" in _schema_cache

    def test_validate_importerror_without_ocsf_lib(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import builtins

        real_import = builtins.__import__

        def mock_import(name: str, *args: object, **kwargs: object) -> object:
            if name.startswith("ocsf"):
                raise ImportError("no ocsf-lib")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)
        with pytest.raises(ImportError, match="ocsf-lib"):
            validate_ocsf_event({})


class TestOpenTelemetryAdapterCoverage:
    """Cover the OTel adapter using unittest.mock to avoid real OTel deps."""

    def _make_adapter(self) -> object:
        from airlog.adapters import OpenTelemetryAdapter

        return OpenTelemetryAdapter()

    def test_init_raises_without_opentelemetry(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import builtins

        real_import = builtins.__import__

        def mock_import(name: str, *args: object, **kwargs: object) -> object:
            if name.startswith("opentelemetry"):
                raise ImportError("no otel")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)
        from airlog.adapters.opentelemetry_adapter import OpenTelemetryAdapter

        with pytest.raises(ImportError, match="opentelemetry-api"):
            OpenTelemetryAdapter()

    def test_emit_adds_event_to_recording_span(self) -> None:
        from unittest.mock import MagicMock, patch

        adapter = self._make_adapter()
        mock_span = MagicMock()
        mock_span.is_recording.return_value = True

        ev = _CapturingStream().record("login", principal=_P, resource="session")
        with patch("opentelemetry.trace.get_current_span", return_value=mock_span):
            adapter.emit(ev)  # type: ignore[union-attr]

        mock_span.add_event.assert_called_once()

    def test_emit_with_tracer_creates_span_when_no_active(self) -> None:
        from unittest.mock import MagicMock, patch

        mock_tracer = MagicMock()
        mock_span = MagicMock()
        mock_span.is_recording.return_value = False
        mock_tracer.start_as_current_span.return_value.__enter__ = MagicMock(return_value=mock_span)
        mock_tracer.start_as_current_span.return_value.__exit__ = MagicMock(return_value=False)

        from airlog.adapters.opentelemetry_adapter import OpenTelemetryAdapter

        adapter = OpenTelemetryAdapter(tracer=mock_tracer)
        ev = _CapturingStream().record("create", principal=_P, resource="doc")

        non_recording = MagicMock()
        non_recording.is_recording.return_value = False

        with patch("opentelemetry.trace.get_current_span", return_value=non_recording):
            adapter.emit(ev)

        mock_tracer.start_as_current_span.assert_called_once_with("audit_event")

    def test_emit_no_tracer_no_active_span_is_noop(self) -> None:
        from unittest.mock import MagicMock, patch

        adapter = self._make_adapter()
        non_recording = MagicMock()
        non_recording.is_recording.return_value = False

        ev = _CapturingStream().record("create", principal=_P, resource="doc")
        with patch("opentelemetry.trace.get_current_span", return_value=non_recording):
            adapter.emit(ev)  # type: ignore[union-attr]
        # no exception = pass

    def test_health_check_healthy(self) -> None:
        adapter = self._make_adapter()
        status = adapter.health_check()  # type: ignore[union-attr]
        assert status.healthy is True

    def test_supports_feature_async_true(self) -> None:
        adapter = self._make_adapter()
        assert adapter.supports_feature(StreamFeature.ASYNC) is True  # type: ignore[union-attr]

    def test_supports_feature_non_async_false(self) -> None:
        adapter = self._make_adapter()
        for feature in StreamFeature:
            if feature != StreamFeature.ASYNC:
                assert adapter.supports_feature(feature) is False  # type: ignore[union-attr]

    def test_aemit_calls_emit(self) -> None:
        from unittest.mock import MagicMock, patch

        adapter = self._make_adapter()
        mock_span = MagicMock()
        mock_span.is_recording.return_value = True

        ev = _CapturingStream().record("login", principal=_P, resource="session")
        with patch("opentelemetry.trace.get_current_span", return_value=mock_span):
            result = asyncio.run(adapter.aemit(ev))  # type: ignore[union-attr]

        assert result is True
        mock_span.add_event.assert_called_once()
