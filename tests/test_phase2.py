"""Tests for airlog Phase 2 features.

Covers:
- context.py  – audit_context / async_audit_context / current_context
- metrics.py  – MetricsAuditStream
- policy.py   – PolicyRouter / PolicyAction / DeliveryError / add_policy
- integrity.py – IntegrityVerificationStream / IntegrityViolation / ReplayableStream
- retention.py – RetentionMiddleware / RetentionRule / RetentionResult / RetentionCapableStream
"""

from __future__ import annotations

import asyncio
import threading
import time
from typing import Any

import pytest

from airlog import (
    AuditEvent,
    AuditStream,
    Principal,
    StreamFeature,
)
from airlog.context import (
    AuditContextData,
    async_audit_context,
    audit_context,
    current_context,
    inject_context,
)
from airlog.integrity import (
    IntegrityVerificationStream,
    IntegrityViolation,
    ReplayableStream,
)
from airlog.metrics import MetricsAuditStream
from airlog.policy import (
    DeliveryError,
    Policy,
    PolicyAction,
    PolicyRouter,
    _set_default_router,
    add_policy,
    get_default_router,
)
from airlog.retention import (
    RetentionCapableStream,
    RetentionMiddleware,
    RetentionResult,
    RetentionRule,
)

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_P = Principal(subject="tester", auth_method="test")


class _CapturingStream(AuditStream):
    """Minimal in-memory AuditStream."""

    def __init__(self) -> None:
        super().__init__()
        self.events: list[AuditEvent] = []
        self._should_raise = False

    def emit(self, event: AuditEvent) -> None:
        if self._should_raise:
            raise RuntimeError("emit failed")
        self.events.append(event)


def _make_event(stream: AuditStream | None = None, **kw: Any) -> AuditEvent:
    s = stream or _CapturingStream()
    return s.record(  # type: ignore[return-value]
        action=kw.pop("action", "test"),
        principal=kw.pop("principal", _P),
        resource=kw.pop("resource", "resource"),
        **kw,
    )


# ===========================================================================
# context.py
# ===========================================================================


class TestAuditContextData:
    def test_defaults_outside_context(self) -> None:
        ctx = current_context()
        assert ctx.correlation_id is None
        assert ctx.principal is None
        assert ctx.metadata == {}

    def test_repr(self) -> None:
        ctx = AuditContextData(correlation_id="cid", principal=_P, metadata={"k": "v"})
        r = repr(ctx)
        assert "cid" in r
        assert "tester" in r


class TestAuditContextSync:
    def test_correlation_id_set(self) -> None:
        with audit_context(correlation_id="req-1") as ctx:
            assert ctx.correlation_id == "req-1"
            assert current_context().correlation_id == "req-1"

    def test_principal_set(self) -> None:
        with audit_context(principal=_P) as ctx:
            assert ctx.principal is _P

    def test_metadata_merged(self) -> None:
        with audit_context(metadata={"env": "prod"}) as ctx:
            assert ctx.metadata["env"] == "prod"

    def test_context_reset_after_exit(self) -> None:
        with audit_context(correlation_id="x"):
            pass
        assert current_context().correlation_id is None

    def test_nested_context_inherits(self) -> None:
        with audit_context(correlation_id="outer"):  # noqa: SIM117
            with audit_context(metadata={"region": "us"}) as inner:
                assert inner.correlation_id == "outer"
                assert inner.metadata["region"] == "us"

    def test_nested_inner_overrides_outer_cid(self) -> None:
        with audit_context(correlation_id="outer"):
            with audit_context(correlation_id="inner") as ctx:
                assert ctx.correlation_id == "inner"
            assert current_context().correlation_id == "outer"

    def test_nested_metadata_merges(self) -> None:
        with audit_context(metadata={"a": "1"}):  # noqa: SIM117
            with audit_context(metadata={"b": "2"}) as ctx:
                assert ctx.metadata["a"] == "1"
                assert ctx.metadata["b"] == "2"

    def test_nested_inner_wins_on_metadata_conflict(self) -> None:
        with audit_context(metadata={"k": "outer"}):  # noqa: SIM117
            with audit_context(metadata={"k": "inner"}) as ctx:
                assert ctx.metadata["k"] == "inner"

    def test_empty_metadata_kwarg(self) -> None:
        with audit_context() as ctx:
            assert ctx.metadata == {}

    def test_yields_audit_context_data(self) -> None:
        with audit_context(correlation_id="c") as ctx:
            assert isinstance(ctx, AuditContextData)

    def test_thread_isolation(self) -> None:
        """Contexts in separate threads must not bleed into each other."""
        results: dict[str, str | None] = {}

        def thread_fn(name: str, cid: str) -> None:
            with audit_context(correlation_id=cid):
                time.sleep(0.01)
                results[name] = current_context().correlation_id

        t1 = threading.Thread(target=thread_fn, args=("t1", "cid-t1"))
        t2 = threading.Thread(target=thread_fn, args=("t2", "cid-t2"))
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        assert results["t1"] == "cid-t1"
        assert results["t2"] == "cid-t2"


class TestAuditContextAsync:
    def test_async_context_sets_values(self) -> None:
        async def _run() -> tuple[str | None, Any]:
            async with async_audit_context(correlation_id="async-1", principal=_P) as ctx:
                return ctx.correlation_id, ctx.principal

        cid, principal = asyncio.run(_run())
        assert cid == "async-1"
        assert principal is _P

    def test_async_context_reset_after_exit(self) -> None:
        async def _run() -> str | None:
            async with async_audit_context(correlation_id="x"):
                pass
            return current_context().correlation_id

        assert asyncio.run(_run()) is None

    def test_async_task_inherits_context(self) -> None:
        """Child tasks should inherit the parent's context copy."""

        async def _child() -> str | None:
            return current_context().correlation_id

        async def _run() -> str | None:
            async with async_audit_context(correlation_id="parent-cid"):
                return await asyncio.create_task(_child())

        assert asyncio.run(_run()) == "parent-cid"


class TestInjectContext:
    def test_inject_returns_explicit_values_when_no_context(self) -> None:
        cid, principal = inject_context(correlation_id="x", principal=_P)
        assert cid == "x"
        assert principal is _P

    def test_inject_fills_nones_from_context(self) -> None:
        with audit_context(correlation_id="ctx-cid", principal=_P):
            cid, principal = inject_context(correlation_id=None, principal=None)
        assert cid == "ctx-cid"
        assert principal is _P

    def test_explicit_overrides_context(self) -> None:
        other = Principal(subject="other", auth_method="jwt")
        with audit_context(correlation_id="ctx-cid"):
            cid, _ = inject_context(correlation_id="explicit", principal=other)
        assert cid == "explicit"


# ===========================================================================
# metrics.py
# ===========================================================================


class TestMetricsAuditStream:
    def _make(self) -> tuple[_CapturingStream, MetricsAuditStream]:
        backend = _CapturingStream()
        metrics = MetricsAuditStream(backend)
        return backend, metrics

    def test_emit_increments_total(self) -> None:
        _, metrics = self._make()
        _make_event(metrics)
        assert metrics.get_metrics()["emit_total"] == 1

    def test_emit_error_increments_error_total(self) -> None:
        backend, metrics = self._make()
        backend._should_raise = True
        with pytest.raises(RuntimeError):
            _make_event(metrics)
        m = metrics.get_metrics()
        assert m["emit_error_total"] == 1
        assert m["emit_total"] == 0

    def test_error_rate(self) -> None:
        backend, metrics = self._make()
        _make_event(metrics)
        backend._should_raise = True
        with pytest.raises(RuntimeError):
            _make_event(metrics)
        m = metrics.get_metrics()
        assert m["error_rate"] == pytest.approx(0.5)

    def test_latency_samples_recorded(self) -> None:
        _, metrics = self._make()
        for _ in range(5):
            _make_event(metrics)
        m = metrics.get_metrics()
        assert m["emit_sample_count"] == 5
        assert m["emit_latency_min_ms"] >= 0.0
        assert m["emit_latency_max_ms"] >= m["emit_latency_min_ms"]

    def test_percentiles_present(self) -> None:
        _, metrics = self._make()
        for _ in range(100):
            _make_event(metrics)
        m = metrics.get_metrics()
        assert "emit_latency_p50_ms" in m
        assert "emit_latency_p95_ms" in m
        assert "emit_latency_p99_ms" in m
        assert m["emit_latency_p99_ms"] >= m["emit_latency_p95_ms"]

    def test_queue_depth_zero_after_emit(self) -> None:
        _, metrics = self._make()
        _make_event(metrics)
        assert metrics.get_metrics()["queue_depth"] == 0

    def test_reset_metrics(self) -> None:
        _, metrics = self._make()
        for _ in range(3):
            _make_event(metrics)
        metrics.reset_metrics()
        m = metrics.get_metrics()
        assert m["emit_total"] == 0
        assert m["emit_sample_count"] == 0

    def test_health_check_delegates(self) -> None:
        _, metrics = self._make()
        hs = metrics.health_check()
        assert isinstance(hs.healthy, bool)

    def test_supports_feature_delegates(self) -> None:
        _, metrics = self._make()
        for feature in StreamFeature:
            assert metrics.supports_feature(feature) is False

    def test_aemit_records_metrics(self) -> None:
        _, metrics = self._make()
        event = _make_event()

        async def _run() -> None:
            await metrics.aemit(event)

        asyncio.run(_run())
        assert metrics.get_metrics()["emit_total"] == 1

    def test_aemit_records_errors(self) -> None:
        backend, metrics = self._make()
        backend._should_raise = True
        event = _make_event()

        async def _run() -> bool:
            return await metrics.aemit(event)

        result = asyncio.run(_run())
        assert result is False
        assert metrics.get_metrics()["emit_error_total"] == 1

    def test_error_rate_zero_when_no_calls(self) -> None:
        _, metrics = self._make()
        assert metrics.get_metrics()["error_rate"] == 0.0

    def test_mean_latency_is_reasonable(self) -> None:
        _, metrics = self._make()
        for _ in range(10):
            _make_event(metrics)
        m = metrics.get_metrics()
        assert m["emit_latency_mean_ms"] >= 0.0

    def test_ring_buffer_bounded(self) -> None:
        """Emit more than _MAX_SAMPLES events – sample list stays bounded."""
        from airlog.metrics import _MAX_SAMPLES

        _, metrics = self._make()
        # Emit slightly more than the cap
        for _ in range(_MAX_SAMPLES + 10):
            _make_event(metrics)
        assert metrics.get_metrics()["emit_sample_count"] <= _MAX_SAMPLES


# ===========================================================================
# policy.py
# ===========================================================================


class TestPolicyAction:
    def test_all_members(self) -> None:
        members = {m.name for m in PolicyAction}
        assert members == {"DROP", "ROUTE", "REQUIRE_BACKEND"}


class TestDeliveryError:
    def test_attributes(self) -> None:
        event = _make_event()
        err = DeliveryError(event, ["backend-a"])
        assert err.event is event
        assert err.failed_backends == ["backend-a"]
        assert "backend-a" in str(err)


class TestPolicyRouterBasics:
    def test_no_backends_no_error(self) -> None:
        router = PolicyRouter()
        router.emit(_make_event())  # should not raise

    def test_register_and_emit(self) -> None:
        backend = _CapturingStream()
        router = PolicyRouter(("default", backend))
        _make_event(router)
        assert len(backend.events) == 1

    def test_deregister_backend(self) -> None:
        backend = _CapturingStream()
        router = PolicyRouter(("x", backend))
        router.deregister_backend("x")
        _make_event(router)
        assert len(backend.events) == 0

    def test_deregister_unknown_raises(self) -> None:
        router = PolicyRouter()
        with pytest.raises(KeyError):
            router.deregister_backend("ghost")


class TestPolicyRouterDrop:
    def test_drop_event(self) -> None:
        backend = _CapturingStream()
        router = PolicyRouter(("b", backend))
        router.add_policy(match=lambda e: e.action == "drop_me", action=PolicyAction.DROP)
        event = _make_event(action="drop_me")
        router.emit(event)
        assert backend.events == []

    def test_non_matching_event_passes_through(self) -> None:
        backend = _CapturingStream()
        router = PolicyRouter(("b", backend))
        router.add_policy(match=lambda e: e.action == "drop_me", action=PolicyAction.DROP)
        event = _make_event(action="keep_me")
        router.emit(event)
        assert len(backend.events) == 1


class TestPolicyRouterRoute:
    def test_route_to_specific_backend(self) -> None:
        backend_a = _CapturingStream()
        backend_b = _CapturingStream()
        router = PolicyRouter(("a", backend_a), ("b", backend_b))
        router.add_policy(
            match=lambda e: e.action == "secret",
            action=PolicyAction.ROUTE,
            backends=["a"],
        )
        event = _make_event(action="secret")
        router.emit(event)
        assert len(backend_a.events) == 1
        assert len(backend_b.events) == 0

    def test_route_unknown_backend_silently_skipped(self) -> None:
        backend = _CapturingStream()
        router = PolicyRouter(("x", backend))
        router.add_policy(
            match=lambda e: True,
            action=PolicyAction.ROUTE,
            backends=["nonexistent"],
        )
        _make_event(router)  # should not raise


class TestPolicyRouterRequireBackend:
    def test_require_backend_success(self) -> None:
        backend = _CapturingStream()
        router = PolicyRouter(("ok", backend))
        router.add_policy(
            match=lambda e: True,
            action=PolicyAction.REQUIRE_BACKEND,
            backends=["ok"],
        )
        _make_event(router)  # should not raise
        assert len(backend.events) == 1

    def test_require_backend_raises_on_failure(self) -> None:
        backend = _CapturingStream()
        backend._should_raise = True
        router = PolicyRouter(("bad", backend))
        router.add_policy(
            match=lambda e: True,
            action=PolicyAction.REQUIRE_BACKEND,
            backends=["bad"],
        )
        with pytest.raises(DeliveryError):
            _make_event(router)

    def test_require_backend_raises_when_no_backends(self) -> None:
        router = PolicyRouter()
        router.add_policy(
            match=lambda e: True,
            action=PolicyAction.REQUIRE_BACKEND,
            backends=["ghost"],
        )
        with pytest.raises(DeliveryError):
            _make_event(router)


class TestPolicyPriority:
    def test_lower_priority_evaluated_first(self) -> None:
        backend = _CapturingStream()
        router = PolicyRouter(("b", backend))
        called: list[int] = []
        router.add_policy(
            match=lambda e: called.append(2) or True,  # type: ignore[func-returns-value]
            action=PolicyAction.DROP,
            priority=2,
        )
        router.add_policy(
            match=lambda e: called.append(1) or True,  # type: ignore[func-returns-value]
            action=PolicyAction.DROP,
            priority=1,
        )
        _make_event(router)
        # priority=1 should be evaluated first
        assert called[0] == 1

    def test_remove_policy(self) -> None:
        backend = _CapturingStream()
        router = PolicyRouter(("b", backend))
        policy = router.add_policy(match=lambda e: True, action=PolicyAction.DROP)
        router.remove_policy(policy)
        _make_event(router)
        assert len(backend.events) == 1

    def test_list_policies(self) -> None:
        router = PolicyRouter()
        p1 = router.add_policy(match=lambda e: True, action=PolicyAction.DROP)
        p2 = router.add_policy(match=lambda e: True, action=PolicyAction.DROP)
        policies = router.list_policies()
        assert p1 in policies
        assert p2 in policies


class TestPolicyRouterAsync:
    def test_aemit_drop(self) -> None:
        backend = _CapturingStream()
        router = PolicyRouter(("b", backend))
        router.add_policy(match=lambda e: True, action=PolicyAction.DROP)
        event = _make_event()

        async def _run() -> bool:
            return await router.aemit(event)

        result = asyncio.run(_run())
        assert result is True
        assert backend.events == []

    def test_aemit_route(self) -> None:
        backend = _CapturingStream()
        router = PolicyRouter(("b", backend))
        router.add_policy(match=lambda e: True, action=PolicyAction.ROUTE, backends=["b"])
        event = _make_event()

        async def _run() -> bool:
            return await router.aemit(event)

        asyncio.run(_run())
        assert len(backend.events) == 1

    def test_aemit_require_backend_failure(self) -> None:
        backend = _CapturingStream()
        backend._should_raise = True
        router = PolicyRouter(("fail", backend))
        router.add_policy(
            match=lambda e: True, action=PolicyAction.REQUIRE_BACKEND, backends=["fail"]
        )
        event = _make_event()

        async def _run() -> None:
            await router.aemit(event)

        with pytest.raises(DeliveryError):
            asyncio.run(_run())


class TestPolicyRouterHealth:
    def test_health_check_no_backends(self) -> None:
        router = PolicyRouter()
        hs = router.health_check()
        assert hs.healthy is True

    def test_health_check_with_backend(self) -> None:
        router = PolicyRouter(("b", _CapturingStream()))
        hs = router.health_check()
        assert hs.healthy is True

    def test_supports_feature(self) -> None:
        router = PolicyRouter()
        for f in StreamFeature:
            assert router.supports_feature(f) is False


class TestAddPolicyModuleLevel:
    def setup_method(self) -> None:
        # Reset module-level router between tests
        _set_default_router(None)

    def teardown_method(self) -> None:
        _set_default_router(None)

    def test_add_policy_returns_policy(self) -> None:
        p = add_policy(match=lambda e: True, action=PolicyAction.DROP)
        assert isinstance(p, Policy)

    def test_get_default_router_returns_same_instance(self) -> None:
        r1 = get_default_router()
        r2 = get_default_router()
        assert r1 is r2


# ===========================================================================
# integrity.py
# ===========================================================================


class _ReplayBackend(ReplayableStream):
    """In-memory replayable backend for testing."""

    def __init__(self) -> None:
        super().__init__()
        self._events: list[AuditEvent] = []

    def emit(self, event: AuditEvent) -> None:
        self._events.append(event)

    def supports_feature(self, feature: StreamFeature) -> bool:
        return feature is StreamFeature.REPLAY

    def replay(self, from_sequence: int = 1, to_sequence: int | None = None) -> list[AuditEvent]:
        result = [e for e in self._events if e.sequence >= from_sequence]
        if to_sequence is not None:
            result = [e for e in result if e.sequence <= to_sequence]
        return result


class TestIntegrityViolation:
    def test_str_missing(self) -> None:
        v = IntegrityViolation(
            event_id="eid",
            sequence=1,
            primary_checksum="abc",
            replica_checksum=None,
            detected_at_ns=0,
            detail="missing",
        )
        assert "MISSING" in str(v)

    def test_str_mismatch(self) -> None:
        v = IntegrityViolation(
            event_id="eid",
            sequence=1,
            primary_checksum="abc" * 22,
            replica_checksum="xyz" * 22,
            detected_at_ns=0,
            detail="mismatch",
        )
        assert "…" in str(v)


class TestIntegrityVerificationStream:
    def _make_ivs(self) -> tuple[_ReplayBackend, _ReplayBackend, IntegrityVerificationStream]:
        primary = _ReplayBackend()
        replica = _ReplayBackend()
        ivs = IntegrityVerificationStream(
            primary=primary,
            replica=replica,
            on_violation=lambda v: None,
            verify_interval_s=9999.0,
        )
        return primary, replica, ivs

    def test_emit_writes_to_both(self) -> None:
        primary, replica, ivs = self._make_ivs()
        _make_event(ivs)
        assert len(primary._events) == 1
        assert len(replica._events) == 1

    def test_verify_now_no_violations_when_in_sync(self) -> None:
        _, _, ivs = self._make_ivs()
        for _ in range(5):
            _make_event(ivs)
        violations = ivs.verify_now()
        assert violations == []

    def test_verify_now_detects_missing_replica_event(self) -> None:
        primary, replica, _ = self._make_ivs()
        violations_found: list[IntegrityViolation] = []
        ivs = IntegrityVerificationStream(
            primary=primary,
            replica=replica,
            on_violation=violations_found.append,
            verify_interval_s=9999.0,
        )
        _make_event(ivs)
        # Remove from replica manually
        replica._events.clear()
        violations = ivs.verify_now()
        assert len(violations) == 1
        assert violations[0].replica_checksum is None

    def test_verify_now_detects_checksum_mismatch(self) -> None:
        import dataclasses

        primary, replica, _ = self._make_ivs()
        violations_found: list[IntegrityViolation] = []
        ivs = IntegrityVerificationStream(
            primary=primary,
            replica=replica,
            on_violation=violations_found.append,
            verify_interval_s=9999.0,
        )
        _make_event(ivs)
        # Tamper replica event checksum
        replica._events[0] = dataclasses.replace(replica._events[0], checksum="deadbeef" * 8)
        violations = ivs.verify_now()
        assert len(violations) == 1
        assert violations[0].replica_checksum == "deadbeef" * 8

    def test_verify_now_no_replay_support_returns_empty(self) -> None:
        backend = _CapturingStream()
        ivs = IntegrityVerificationStream(
            primary=backend,
            replica=backend,
            on_violation=lambda v: None,
        )
        _make_event(ivs)
        assert ivs.verify_now() == []

    def test_health_check_healthy(self) -> None:
        _, _, ivs = self._make_ivs()
        hs = ivs.health_check()
        assert hs.healthy is True

    def test_supports_feature_both_required(self) -> None:
        primary = _ReplayBackend()
        replica = _CapturingStream()
        ivs = IntegrityVerificationStream(
            primary=primary, replica=replica, on_violation=lambda v: None
        )
        assert ivs.supports_feature(StreamFeature.REPLAY) is False

    def test_start_stop(self) -> None:
        _, _, ivs = self._make_ivs()
        ivs.start()
        assert ivs._running is True
        ivs.stop()
        assert ivs._running is False

    def test_start_idempotent(self) -> None:
        _, _, ivs = self._make_ivs()
        ivs.start()
        ivs.start()  # second call should not raise
        ivs.stop()

    def test_aemit(self) -> None:
        primary, _replica, ivs = self._make_ivs()
        event = _make_event()

        async def _run() -> bool:
            return await ivs.aemit(event)

        result = asyncio.run(_run())
        assert result is True
        assert len(primary._events) == 1

    def test_callback_called_on_violation(self) -> None:
        primary, replica, _ = self._make_ivs()
        called: list[IntegrityViolation] = []
        ivs = IntegrityVerificationStream(
            primary=primary,
            replica=replica,
            on_violation=called.append,
            verify_interval_s=9999.0,
        )
        _make_event(ivs)
        replica._events.clear()
        ivs.verify_now()
        assert len(called) == 1


# ===========================================================================
# retention.py
# ===========================================================================


class _RetentionBackend(RetentionCapableStream):
    """In-memory retention-capable backend for testing."""

    def __init__(self) -> None:
        super().__init__()
        self._events: list[AuditEvent] = []
        self.retention_calls: list[RetentionRule] = []

    def emit(self, event: AuditEvent) -> None:
        self._events.append(event)

    def supports_feature(self, feature: StreamFeature) -> bool:
        return feature is StreamFeature.RETENTION

    def apply_retention(self, rule: RetentionRule) -> RetentionResult:
        self.retention_calls.append(rule)
        return RetentionResult(
            rule=rule,
            backend_name="test",
            affected_count=len(self._events),
            success=True,
            message=f"Applied {rule.action}",
        )


class TestRetentionRule:
    def test_defaults(self) -> None:
        rule = RetentionRule(age_days=30, action="delete")
        assert rule.enabled is True
        assert rule.target_backend == ""
        assert rule.filters == {}

    def test_custom_fields(self) -> None:
        rule = RetentionRule(
            age_days=90,
            action="archive",
            target_backend="s3",
            filters={"resource": "payment"},
        )
        assert rule.target_backend == "s3"
        assert rule.filters["resource"] == "payment"


class TestRetentionResult:
    def test_defaults(self) -> None:
        rule = RetentionRule(age_days=1, action="delete")
        result = RetentionResult(rule=rule, backend_name="db")
        assert result.success is True
        assert result.affected_count == 0


class TestRetentionMiddleware:
    def _make(self) -> tuple[_RetentionBackend, RetentionMiddleware]:
        backend = _RetentionBackend()
        mw = RetentionMiddleware(
            backends={"db": backend},
            rules=[RetentionRule(age_days=30, action="archive")],
        )
        return backend, mw

    def test_run_now_calls_apply_retention(self) -> None:
        backend, mw = self._make()
        results = mw.run_now()
        assert len(results) == 1
        assert results[0].success is True
        assert len(backend.retention_calls) == 1

    def test_skips_non_retention_backend(self) -> None:
        non_retention = _CapturingStream()
        mw = RetentionMiddleware(
            backends={"capture": non_retention},
            rules=[RetentionRule(age_days=30, action="delete")],
        )
        results = mw.run_now()
        assert results == []

    def test_disabled_rule_skipped(self) -> None:
        backend = _RetentionBackend()
        rule = RetentionRule(age_days=30, action="delete", enabled=False)
        mw = RetentionMiddleware(backends={"db": backend}, rules=[rule])
        results = mw.run_now()
        assert results == []

    def test_on_result_callback_called(self) -> None:
        backend = _RetentionBackend()
        callback_results: list[RetentionResult] = []
        mw = RetentionMiddleware(
            backends={"db": backend},
            rules=[RetentionRule(age_days=30, action="archive")],
            on_result=callback_results.append,
        )
        mw.run_now()
        assert len(callback_results) == 1

    def test_history_accumulated(self) -> None:
        _, mw = self._make()
        mw.run_now()
        mw.run_now()
        assert len(mw.get_history()) == 2

    def test_clear_history(self) -> None:
        _, mw = self._make()
        mw.run_now()
        mw.clear_history()
        assert mw.get_history() == []

    def test_add_and_remove_rule(self) -> None:
        _, mw = self._make()
        rule = RetentionRule(age_days=7, action="compress")
        mw.add_rule(rule)
        assert rule in mw.list_rules()
        mw.remove_rule(rule)
        assert rule not in mw.list_rules()

    def test_remove_unknown_rule_raises(self) -> None:
        _, mw = self._make()
        rule = RetentionRule(age_days=999, action="delete")
        with pytest.raises(ValueError):
            mw.remove_rule(rule)

    def test_start_stop(self) -> None:
        _, mw = self._make()
        mw.start()
        assert mw._running is True
        mw.stop()
        assert mw._running is False

    def test_start_idempotent(self) -> None:
        _, mw = self._make()
        mw.start()
        mw.start()  # second call is a no-op
        mw.stop()

    def test_backend_exception_captured_in_result(self) -> None:
        class _BrokenBackend(RetentionCapableStream):
            def emit(self, event: AuditEvent) -> None:
                pass

            def supports_feature(self, feature: StreamFeature) -> bool:
                return feature is StreamFeature.RETENTION

            def apply_retention(self, rule: RetentionRule) -> RetentionResult:
                raise RuntimeError("storage unavailable")

        mw = RetentionMiddleware(
            backends={"broken": _BrokenBackend()},
            rules=[RetentionRule(age_days=1, action="delete")],
        )
        results = mw.run_now()
        assert len(results) == 1
        assert results[0].success is False
        assert "storage unavailable" in results[0].message

    def test_multiple_backends_and_rules(self) -> None:
        b1 = _RetentionBackend()
        b2 = _RetentionBackend()
        rules = [
            RetentionRule(age_days=30, action="archive"),
            RetentionRule(age_days=90, action="delete"),
        ]
        mw = RetentionMiddleware(backends={"a": b1, "b": b2}, rules=rules)
        results = mw.run_now()
        # 2 backends x 2 rules = 4 results
        assert len(results) == 4
