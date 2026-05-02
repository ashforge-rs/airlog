"""Compliance test base class for airlog backend implementations.

Import :class:`BackendComplianceTest` in your test suite and subclass it to
verify that a custom :class:`~airlog.interfaces.AuditStream` meets the
airlog contract.

Example::

    # tests/test_my_backend.py
    import pytest
    from airlog.testing import BackendComplianceTest
    from myapp.audit import MyDatabaseStream

    class TestMyDatabaseStream(BackendComplianceTest):
        @pytest.fixture
        def stream(self):
            s = MyDatabaseStream(dsn=":memory:")
            yield s
            s.close()

Running the test suite will automatically execute all compliance checks
defined on :class:`BackendComplianceTest`.
"""

from __future__ import annotations

import asyncio
import dataclasses
import threading
from typing import Any

import pytest

from airlog.interfaces import AuditEvent, AuditStream, HealthStatus, Principal, StreamFeature

__all__ = ["BackendComplianceTest"]

_PRINCIPAL = Principal(subject="compliance-test", auth_method="test")


def _make_event(stream: AuditStream, **overrides: Any) -> AuditEvent:
    """Helper: record a minimal event on *stream*, applying field overrides."""
    defaults: dict[str, Any] = dict(
        action="compliance_check",
        principal=_PRINCIPAL,
        resource="test_resource",
    )
    defaults.update(overrides)
    return stream.record(**defaults)  # type: ignore[arg-type]


class BackendComplianceTest:
    """Pytest base class for backend compliance testing.

    Subclass this in your own test module and provide a ``stream`` fixture
    that yields a fresh :class:`~airlog.interfaces.AuditStream` instance.

    All test methods defined here are automatically inherited and run when
    pytest collects the subclass.

    Example::

        class TestMyStream(BackendComplianceTest):
            @pytest.fixture
            def stream(self):
                return MyStream()
    """

    @pytest.fixture
    def stream(self) -> AuditStream:
        """Override in your subclass to provide the backend under test.

        Raises:
            NotImplementedError: Always – subclasses must override this.
        """
        raise NotImplementedError(  # pragma: no cover
            "Subclasses of BackendComplianceTest must provide a 'stream' fixture."
        )

    # ------------------------------------------------------------------
    # Ordering
    # ------------------------------------------------------------------

    def test_sequence_is_monotonically_increasing(self, stream: AuditStream) -> None:
        """Events emitted in order must have strictly increasing sequence numbers."""
        events = [_make_event(stream, action=f"op_{i}") for i in range(5)]
        seqs = [e.sequence for e in events]
        assert seqs == sorted(seqs), f"Sequences are not monotonically increasing: {seqs}"
        assert len(set(seqs)) == len(seqs), f"Duplicate sequence numbers detected: {seqs}"

    def test_first_sequence_is_positive(self, stream: AuditStream) -> None:
        """The first emitted event must have a sequence number ≥ 1."""
        event = _make_event(stream)
        assert event.sequence >= 1

    def test_event_id_is_unique(self, stream: AuditStream) -> None:
        """Every emitted event must have a globally unique ``event_id``."""
        ids = {_make_event(stream).event_id for _ in range(20)}
        assert len(ids) == 20, "Duplicate event IDs detected"

    def test_concurrent_sequence_safety(self, stream: AuditStream) -> None:
        """Concurrent ``record()`` calls must produce gap-free sequences."""
        n = 50
        events: list[AuditEvent] = []
        lock = threading.Lock()

        def worker() -> None:
            ev = _make_event(stream)
            with lock:
                events.append(ev)

        threads = [threading.Thread(target=worker) for _ in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        seqs = sorted(e.sequence for e in events)
        assert seqs == list(range(seqs[0], seqs[0] + n)), f"Gaps detected in sequences: {seqs}"

    # ------------------------------------------------------------------
    # Integrity
    # ------------------------------------------------------------------

    def test_checksum_valid_on_emit(self, stream: AuditStream) -> None:
        """Events returned by ``record()`` must pass :meth:`~AuditEvent.verify`."""
        event = _make_event(stream)
        assert event.verify(), "Checksum verification failed for newly emitted event"

    def test_checksum_survives_round_trip(self, stream: AuditStream) -> None:
        """Serializing and deserializing an event must not alter its checksum."""
        import json

        event = _make_event(stream)
        raw = json.dumps(event.to_dict())  # type: ignore[arg-type]
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
        assert reconstructed.verify(), "Checksum failed after JSON round-trip"

    def test_tampered_event_fails_verify(self, stream: AuditStream) -> None:
        """Mutating a field must invalidate the checksum."""
        event = _make_event(stream)
        tampered = dataclasses.replace(event, action="tampered_action")
        assert not tampered.verify(), "Tampered event unexpectedly passed verify()"

    # ------------------------------------------------------------------
    # Graceful error handling
    # ------------------------------------------------------------------

    def test_emit_does_not_raise_on_valid_event(self, stream: AuditStream) -> None:
        """``emit()`` must not raise for a well-formed event."""
        event = _make_event(stream)
        try:
            stream.emit(event)
        except Exception as exc:
            pytest.fail(f"emit() raised unexpectedly: {exc}")

    def test_health_check_returns_health_status(self, stream: AuditStream) -> None:
        """``health_check()`` must return a :class:`~airlog.interfaces.HealthStatus`."""
        status = stream.health_check()
        assert isinstance(status, HealthStatus), (
            f"health_check() returned {type(status)!r}, expected HealthStatus"
        )
        assert isinstance(status.healthy, bool)
        assert isinstance(status.latency_ms, float)
        assert isinstance(status.message, str)

    def test_supports_feature_returns_bool(self, stream: AuditStream) -> None:
        """``supports_feature()`` must return a ``bool`` for every feature."""
        for feature in StreamFeature:
            result = stream.supports_feature(feature)
            assert isinstance(result, bool), (
                f"supports_feature({feature!r}) returned {type(result)!r}, expected bool"
            )

    # ------------------------------------------------------------------
    # Async bridge
    # ------------------------------------------------------------------

    def test_aemit_returns_bool(self, stream: AuditStream) -> None:
        """``aemit()`` must return a bool indicating success."""
        event = _make_event(stream)

        async def _run() -> bool:
            return await stream.aemit(event)

        result = asyncio.run(_run())
        assert isinstance(result, bool), f"aemit() returned {type(result)!r}, expected bool"

    def test_aemit_accepts_valid_event(self, stream: AuditStream) -> None:
        """``aemit()`` must not raise for a well-formed event."""
        event = _make_event(stream)

        async def _run() -> bool:
            return await stream.aemit(event)

        try:
            asyncio.run(_run())
        except Exception as exc:
            pytest.fail(f"aemit() raised unexpectedly: {exc}")
