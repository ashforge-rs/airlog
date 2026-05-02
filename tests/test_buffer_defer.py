"""Tests for airlog.buffer and airlog.defer.

Covers:
- BatchEnvelope construction, to_dict, verify (good and tampered)
- BufferHealth and BufferStatus thresholds
- BufferedStream: basic emit/flush_sync, WAL write/replay/delete,
  size-threshold auto-flush, byte-threshold, alert_backend,
  all four ErrorPolicy branches (overflow and flush failure),
  async flush(), health_check, supports_feature, stop/timer lifecycle,
  flush_all, _deserialize_event round-trip
- defer_context: normal, nested, exception + DROP, exception + non-DROP,
  _flush_deferred error suppression, _try_defer outside context
- async_defer_context: normal, nested, exception + DROP, exception + non-DROP
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import tempfile
import warnings

import pytest

from airlog.buffer import (
    BatchEnvelope,
    BufferedStream,
    BufferStatus,
    ErrorPolicy,
    _deserialize_event,
    flush_all,
)
from airlog.defer import _flush_deferred, _try_defer, async_defer_context, defer_context
from airlog.interfaces import AuditEvent, AuditStream, Principal, StreamFeature

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_P = Principal(subject="alice", auth_method="password")


class _Sink(AuditStream):
    """Minimal recording stream."""

    def __init__(self) -> None:
        super().__init__()
        self.events: list[AuditEvent] = []

    def emit(self, event: AuditEvent) -> None:
        self.events.append(event)


class _FailingSink(AuditStream):
    """Stream that raises on every emit."""

    def __init__(self, exc: Exception | None = None) -> None:
        super().__init__()
        self._exc = exc or RuntimeError("backend failure")

    def emit(self, event: AuditEvent) -> None:
        raise self._exc


def _make_buf(
    backend: AuditStream | None = None,
    *,
    flush_interval: float | None = None,
    max_buffer_size: int = 100,
    max_buffer_bytes: int = 10 * 1024 * 1024,
    error_policy: ErrorPolicy = ErrorPolicy.DROP,
    wal_path: str | None = None,
    alert_backend: AuditStream | None = None,
    dead_letter_backend: AuditStream | None = None,
) -> BufferedStream:
    if backend is None:
        backend = _Sink()
    return BufferedStream(
        backend,
        flush_interval=flush_interval,
        max_buffer_size=max_buffer_size,
        max_buffer_bytes=max_buffer_bytes,
        error_policy=error_policy,
        wal_path=wal_path,
        alert_backend=alert_backend,
        dead_letter_backend=dead_letter_backend,
    )


def _record(buf: BufferedStream, action: str = "act") -> AuditEvent:
    return buf.record(action, principal=_P, resource="res")


# ---------------------------------------------------------------------------
# BatchEnvelope
# ---------------------------------------------------------------------------


class TestBatchEnvelope:
    def _events(self, n: int) -> list[AuditEvent]:
        sink = _Sink()
        buf = _make_buf(sink)
        for i in range(n):
            _record(buf, f"action_{i}")
        buf.flush_sync()
        return sink.events

    def test_from_events_empty_raises(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            BatchEnvelope.from_events([])

    def test_from_events_single(self) -> None:
        evts = self._events(1)
        env = BatchEnvelope.from_events(evts)
        assert env.event_count == 1
        assert env.first_seq == env.last_seq == evts[0].sequence
        assert env.verify()

    def test_from_events_multiple(self) -> None:
        evts = self._events(5)
        env = BatchEnvelope.from_events(evts)
        assert env.event_count == 5
        assert env.first_seq == evts[0].sequence
        assert env.last_seq == evts[-1].sequence
        assert env.verify()

    def test_to_dict_keys(self) -> None:
        evts = self._events(2)
        d = BatchEnvelope.from_events(evts).to_dict()
        assert set(d) >= {
            "batch_id",
            "first_seq",
            "last_seq",
            "event_count",
            "batch_checksum",
            "events",
        }
        assert len(d["events"]) == 2

    def test_verify_fails_wrong_event_count(self) -> None:
        evts = self._events(2)
        env = BatchEnvelope.from_events(evts)
        # Corrupt the declared count
        env2 = BatchEnvelope(
            batch_id=env.batch_id,
            first_seq=env.first_seq,
            last_seq=env.last_seq,
            event_count=99,  # wrong
            batch_checksum=env.batch_checksum,
            events=env.events,
        )
        assert not env2.verify()

    def test_verify_fails_wrong_seq_bounds(self) -> None:
        evts = self._events(2)
        env = BatchEnvelope.from_events(evts)
        env2 = BatchEnvelope(
            batch_id=env.batch_id,
            first_seq=0,  # wrong
            last_seq=env.last_seq,
            event_count=env.event_count,
            batch_checksum=env.batch_checksum,
            events=env.events,
        )
        assert not env2.verify()

    def test_verify_fails_wrong_checksum(self) -> None:
        evts = self._events(2)
        env = BatchEnvelope.from_events(evts)
        env2 = BatchEnvelope(
            batch_id=env.batch_id,
            first_seq=env.first_seq,
            last_seq=env.last_seq,
            event_count=env.event_count,
            batch_checksum="deadbeef",
            events=env.events,
        )
        assert not env2.verify()

    def test_verify_fails_empty_events_list(self) -> None:
        evts = self._events(1)
        env = BatchEnvelope.from_events(evts)
        env2 = BatchEnvelope(
            batch_id=env.batch_id,
            first_seq=env.first_seq,
            last_seq=env.last_seq,
            event_count=0,
            batch_checksum=env.batch_checksum,
            events=[],
        )
        assert not env2.verify()


# ---------------------------------------------------------------------------
# BufferHealth / BufferStatus
# ---------------------------------------------------------------------------


class TestBufferHealth:
    def test_ok_when_empty(self) -> None:
        buf = _make_buf(max_buffer_size=10)
        h = buf.buffer_health()
        assert h.status is BufferStatus.OK
        assert h.event_count == 0
        assert h.pct_full == 0.0

    def test_warning_at_80_pct(self) -> None:
        buf = _make_buf(max_buffer_size=10)
        for _ in range(8):
            _record(buf)
        h = buf.buffer_health()
        assert h.status is BufferStatus.WARNING
        assert h.pct_full >= 0.8

    def test_blocking_at_100_pct(self) -> None:
        buf = _make_buf(max_buffer_size=10, max_buffer_bytes=10 * 1024 * 1024)
        # Force internal state so pct_full == 1.0
        buf._buffer_bytes = buf._max_buffer_bytes
        h = buf.buffer_health()
        assert h.status is BufferStatus.BLOCKING
        assert h.pct_full == 1.0

    def test_byte_threshold_drives_pct(self) -> None:
        buf = _make_buf(max_buffer_size=1000, max_buffer_bytes=100)
        # Simulate byte fill by setting internal state directly
        buf._buffer_bytes = 90  # 90% full by bytes
        h = buf.buffer_health()
        assert h.pct_full >= 0.9

    def test_zero_max_size_doesnt_divide_by_zero(self) -> None:
        buf = _make_buf(max_buffer_size=0)
        h = buf.buffer_health()
        assert isinstance(h.pct_full, float)


# ---------------------------------------------------------------------------
# BufferedStream — basic emit / flush_sync
# ---------------------------------------------------------------------------


class TestBufferedStreamBasic:
    def test_events_held_until_flush(self) -> None:
        sink = _Sink()
        buf = _make_buf(sink)
        _record(buf)
        _record(buf)
        assert len(sink.events) == 0
        buf.flush_sync()
        assert len(sink.events) == 2

    def test_flush_sync_is_idempotent_on_empty(self) -> None:
        buf = _make_buf()
        buf.flush_sync()  # no error on empty buffer
        buf.flush_sync()

    def test_flush_sync_clears_buffer(self) -> None:
        sink = _Sink()
        buf = _make_buf(sink)
        _record(buf)
        buf.flush_sync()
        assert buf.buffer_health().event_count == 0

    def test_events_arrive_in_order(self) -> None:
        sink = _Sink()
        buf = _make_buf(sink)
        for i in range(10):
            buf.record(f"act_{i}", principal=_P, resource="r")
        buf.flush_sync()
        actions = [e.action for e in sink.events]
        assert actions == [f"act_{i}" for i in range(10)]

    def test_supports_feature_batching(self) -> None:
        buf = _make_buf()
        assert buf.supports_feature(StreamFeature.BATCHING)

    def test_supports_feature_delegates(self) -> None:
        buf = _make_buf()
        # QUERY is not advertised by _Sink or BufferedStream
        assert not buf.supports_feature(StreamFeature.QUERY)

    def test_health_check_healthy_backend(self) -> None:
        buf = _make_buf()
        h = buf.health_check()
        assert h.healthy

    def test_health_check_unhealthy_when_buffer_full(self) -> None:
        buf = _make_buf(max_buffer_size=10)
        # Simulate BLOCKING state via internal state
        buf._buffer_bytes = buf._max_buffer_bytes
        h = buf.health_check()
        assert not h.healthy

    def test_health_check_unhealthy_backend(self) -> None:
        class _UnhealthySink(_Sink):
            from airlog.interfaces import HealthStatus

            def health_check(self) -> HealthStatus:
                from airlog.interfaces import HealthStatus

                return HealthStatus(healthy=False, latency_ms=0.0, message="down")

        buf = _make_buf(_UnhealthySink())
        h = buf.health_check()
        assert not h.healthy


# ---------------------------------------------------------------------------
# BufferedStream — async flush
# ---------------------------------------------------------------------------


class TestBufferedStreamAsyncFlush:
    def test_async_flush_drains_buffer(self) -> None:
        sink = _Sink()
        buf = _make_buf(sink)
        _record(buf)
        asyncio.run(buf.flush())
        assert len(sink.events) == 1


# ---------------------------------------------------------------------------
# BufferedStream — timer-based flush
# ---------------------------------------------------------------------------


class TestBufferedStreamTimer:
    def test_timer_flushes_after_interval(self) -> None:
        sink = _Sink()
        buf = BufferedStream(sink, flush_interval=0.05, max_buffer_size=1000)
        buf.record("timed", principal=_P, resource="r")
        # Wait long enough for the timer to fire
        for _ in range(40):
            if sink.events:
                break
            import time

            time.sleep(0.01)
        buf.stop()
        assert len(sink.events) == 1

    def test_stop_cancels_timer_and_flushes(self) -> None:
        sink = _Sink()
        buf = BufferedStream(sink, flush_interval=10.0, max_buffer_size=1000)
        buf.record("stopping", principal=_P, resource="r")
        buf.stop()
        assert len(sink.events) == 1

    def test_stop_is_idempotent(self) -> None:
        buf = _make_buf()
        buf.stop()
        buf.stop()  # second call is a no-op

    def test_schedule_timer_skips_when_stopped(self) -> None:
        buf = _make_buf()
        buf._stopped = True
        buf._schedule_timer()  # should not create a timer
        assert buf._timer is None


# ---------------------------------------------------------------------------
# BufferedStream — size-threshold auto-flush
# ---------------------------------------------------------------------------


class TestBufferedStreamThreshold:
    def test_auto_flush_at_max_size(self) -> None:
        sink = _Sink()
        buf = _make_buf(sink, max_buffer_size=3)
        for _ in range(3):
            _record(buf)
        # Give the background flush thread a moment
        import time

        time.sleep(0.1)
        assert len(sink.events) == 3


# ---------------------------------------------------------------------------
# BufferedStream — ErrorPolicy overflow branches
# ---------------------------------------------------------------------------


class TestErrorPolicyOverflow:
    def _fill_buffer(self, buf: BufferedStream) -> None:
        """Pre-fill the buffer to max capacity via internal state (no threading)."""
        from airlog.interfaces import Principal

        p = Principal(subject="s", auth_method="m")
        # Create a dummy event and fill the buffer directly to avoid auto-flush race
        evt = buf.record("seed", principal=p, resource="r")
        # ensure buffer is full: set _buffer to max_buffer_size items
        with buf._buffer_lock:
            while len(buf._buffer) < buf._max_buffer_size:
                buf._buffer.append((None, evt))

    def test_drop_emits_warning(self) -> None:
        sink = _Sink()
        buf = _make_buf(sink, max_buffer_size=5, error_policy=ErrorPolicy.DROP)
        self._fill_buffer(buf)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            _record(buf)  # overflows
        assert any("dropping event" in str(w.message) for w in caught)

    def test_panic_raises(self) -> None:
        buf = _make_buf(max_buffer_size=5, error_policy=ErrorPolicy.PANIC)
        self._fill_buffer(buf)
        with pytest.raises(RuntimeError, match="buffer full"):
            _record(buf)

    def test_dead_letter_with_backend(self) -> None:
        dl_sink = _Sink()
        buf = _make_buf(
            max_buffer_size=5,
            error_policy=ErrorPolicy.DEAD_LETTER,
            dead_letter_backend=dl_sink,
        )
        self._fill_buffer(buf)
        _record(buf)  # overflow -> dead letter
        assert len(dl_sink.events) == 1

    def test_dead_letter_without_backend_warns(self) -> None:
        buf = _make_buf(max_buffer_size=5, error_policy=ErrorPolicy.DEAD_LETTER)
        self._fill_buffer(buf)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            _record(buf)
        assert any("DEAD_LETTER" in str(w.message) for w in caught)

    def test_retry_succeeds_after_flush(self) -> None:
        sink = _Sink()
        buf = _make_buf(sink, max_buffer_size=5, error_policy=ErrorPolicy.RETRY)
        buf._RETRY_SLEEP_S = 0.0  # speed up test
        self._fill_buffer(buf)
        # RETRY flushes first then fits
        _record(buf)
        buf.flush_sync()
        assert len(sink.events) >= 1  # at least the retry event got through

    def test_retry_exhausted_warns(self) -> None:
        sink = _Sink()
        buf = _make_buf(sink, max_buffer_size=5, error_policy=ErrorPolicy.RETRY)
        buf._RETRY_SLEEP_S = 0.0
        buf._RETRY_ATTEMPTS = 1
        self._fill_buffer(buf)

        # Patch flush_sync to not drain so retry always finds buffer full
        original_flush = buf.flush_sync

        def no_op_flush() -> None:
            pass  # don't drain

        buf.flush_sync = no_op_flush  # type: ignore[method-assign]
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            _record(buf)
        buf.flush_sync = original_flush  # restore
        assert any(
            "retry exhausted" in str(w.message) or "dropping event" in str(w.message)
            for w in caught
        )


# ---------------------------------------------------------------------------
# BufferedStream — ErrorPolicy flush-failure branches
# ---------------------------------------------------------------------------


class TestErrorPolicyFlushFailure:
    def test_drop_on_flush_failure_warns(self) -> None:
        buf = _make_buf(_FailingSink(), error_policy=ErrorPolicy.DROP)
        _record(buf)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            buf.flush_sync()
        assert any("flush failed" in str(w.message) for w in caught)

    def test_panic_on_flush_failure_raises(self) -> None:
        buf = _make_buf(_FailingSink(), error_policy=ErrorPolicy.PANIC)
        _record(buf)
        with pytest.raises(RuntimeError, match="backend failure"):
            buf.flush_sync()

    def test_dead_letter_on_flush_failure(self) -> None:
        dl = _Sink()
        buf = BufferedStream(
            _FailingSink(),
            flush_interval=None,
            error_policy=ErrorPolicy.DEAD_LETTER,
            dead_letter_backend=dl,
        )
        _record(buf)
        buf.flush_sync()
        assert len(dl.events) == 1

    def test_retry_on_flush_failure_returns_events_to_buffer(self) -> None:
        buf = _make_buf(_FailingSink(), error_policy=ErrorPolicy.RETRY)
        _record(buf)
        buf.flush_sync()  # fails -> events returned to buffer
        assert buf.buffer_health().event_count == 1


# ---------------------------------------------------------------------------
# BufferedStream — alert_backend
# ---------------------------------------------------------------------------


class TestAlertBackend:
    def test_alert_emitted_at_warning_threshold(self) -> None:
        alert_sink = _Sink()
        buf = _make_buf(alert_backend=alert_sink, max_buffer_size=10)
        # 8/10 = 80% -> warning threshold
        for _ in range(8):
            _record(buf)
        assert any(e.action == "buffer_warning" for e in alert_sink.events)

    def test_no_alert_below_threshold(self) -> None:
        alert_sink = _Sink()
        buf = _make_buf(alert_backend=alert_sink, max_buffer_size=10)
        for _ in range(7):  # 70% - below threshold
            _record(buf)
        assert not any(e.action == "buffer_warning" for e in alert_sink.events)

    def test_no_alert_without_backend(self) -> None:
        # Should not raise when alert_backend is None
        buf = _make_buf(max_buffer_size=10)
        for _ in range(8):
            _record(buf)


# ---------------------------------------------------------------------------
# BufferedStream — WAL
# ---------------------------------------------------------------------------


class TestWAL:
    def test_wal_persists_and_replays(self) -> None:
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            wal_path = f.name
        try:
            sink1 = _Sink()
            buf1 = BufferedStream(
                sink1, flush_interval=None, max_buffer_size=100, wal_path=wal_path
            )
            buf1.record("wal_event", principal=_P, resource="r")
            # Close without flushing so WAL has an unflushed entry
            if buf1._wal_conn:
                buf1._wal_conn.close()
                buf1._wal_conn = None
            buf1._stopped = True

            # Open a new BufferedStream against the same WAL - should replay
            sink2 = _Sink()
            buf2 = BufferedStream(
                sink2, flush_interval=None, max_buffer_size=100, wal_path=wal_path
            )
            assert buf2.buffer_health().event_count == 1
            buf2.flush_sync()
            assert len(sink2.events) == 1
            assert sink2.events[0].action == "wal_event"
        finally:
            with contextlib.suppress(OSError):
                os.unlink(wal_path)

    def test_wal_entries_deleted_after_flush(self) -> None:
        import contextlib

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            wal_path = f.name
        try:
            buf = BufferedStream(
                _Sink(), flush_interval=None, max_buffer_size=100, wal_path=wal_path
            )
            buf.record("evt", principal=_P, resource="r")
            buf.flush_sync()
            # WAL should be empty now
            import sqlite3

            conn = sqlite3.connect(wal_path)
            rows = conn.execute("SELECT COUNT(*) FROM wal_events").fetchone()[0]
            conn.close()
            assert rows == 0
        finally:
            with contextlib.suppress(OSError):
                os.unlink(wal_path)

    def test_corrupt_wal_entry_skipped(self) -> None:
        import contextlib
        import sqlite3

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            wal_path = f.name
        try:
            # Manually insert a corrupt WAL row
            conn = sqlite3.connect(wal_path)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS wal_events "
                "(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                "event_json TEXT NOT NULL, created_at REAL NOT NULL)"
            )
            conn.execute(
                "INSERT INTO wal_events (event_json, created_at) VALUES (?, ?)",
                ("not valid json {{{{", 0.0),
            )
            conn.commit()
            conn.close()

            sink = _Sink()
            buf = BufferedStream(sink, flush_interval=None, max_buffer_size=100, wal_path=wal_path)
            # Corrupt entry should be skipped, buffer should be empty
            assert buf.buffer_health().event_count == 0
        finally:
            with contextlib.suppress(OSError):
                os.unlink(wal_path)

    def test_stop_closes_wal(self) -> None:
        import contextlib

        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            wal_path = f.name
        try:
            buf = BufferedStream(
                _Sink(), flush_interval=None, max_buffer_size=100, wal_path=wal_path
            )
            buf.stop()
            assert buf._wal_conn is None
        finally:
            with contextlib.suppress(OSError):
                os.unlink(wal_path)


# ---------------------------------------------------------------------------
# flush_all
# ---------------------------------------------------------------------------


class TestFlushAll:
    def test_flush_all_drains_multiple_buffers(self) -> None:
        sinks = [_Sink() for _ in range(3)]
        bufs = [_make_buf(s) for s in sinks]
        for buf in bufs:
            _record(buf)
        flush_all()
        for sink in sinks:
            assert len(sink.events) == 1

    def test_flush_all_skips_dead_refs(self) -> None:
        # GC'd buffer should not cause errors
        sink = _Sink()
        buf = _make_buf(sink)
        _record(buf)
        del buf  # allow GC
        flush_all()  # should not raise


# ---------------------------------------------------------------------------
# _deserialize_event
# ---------------------------------------------------------------------------


class TestDeserializeEvent:
    def _serialise(self) -> str:
        sink = _Sink()
        buf = _make_buf(sink)
        buf.record("test", principal=_P, resource="res", resource_id="r1", correlation_id="c1")
        buf.flush_sync()
        return json.dumps(sink.events[0]._as_dict())

    def test_round_trip(self) -> None:
        raw = self._serialise()
        event = _deserialize_event(raw)
        assert event.action == "test"
        assert event.principal.subject == "alice"
        assert event.resource_id == "r1"
        assert event.correlation_id == "c1"

    def test_invalid_json_raises(self) -> None:
        with pytest.raises(json.JSONDecodeError):
            _deserialize_event("not json")

    def test_missing_field_raises(self) -> None:
        with pytest.raises(KeyError):
            _deserialize_event(json.dumps({"principal": {"subject": "x", "auth_method": "y"}}))


# ---------------------------------------------------------------------------
# defer_context — synchronous
# ---------------------------------------------------------------------------


class TestDeferContext:
    def test_basic_defer_stages_then_flushes(self) -> None:
        sink = _Sink()
        buf = _make_buf(sink)
        with defer_context():
            _record(buf, "a")
            _record(buf, "b")
            assert len(sink.events) == 0
        # After context exit events are in buffer; flush to confirm
        buf.flush_sync()
        assert len(sink.events) == 2

    def test_defer_drop_on_exception(self) -> None:
        sink = _Sink()
        buf = _make_buf(sink)
        with pytest.raises(RuntimeError), defer_context(on_error=ErrorPolicy.DROP):
            _record(buf, "gone")
            raise RuntimeError("boom")
        buf.flush_sync()
        assert len(sink.events) == 0

    def test_defer_flush_on_exception_with_non_drop_policy(self) -> None:
        sink = _Sink()
        buf = _make_buf(sink)
        with pytest.raises(ValueError), defer_context(on_error=ErrorPolicy.PANIC):
            _record(buf, "kept")
            raise ValueError("oops")
        buf.flush_sync()
        assert len(sink.events) == 1

    def test_nested_defer_merges_into_outermost(self) -> None:
        sink = _Sink()
        buf = _make_buf(sink)
        with defer_context():
            _record(buf, "outer_1")
            with defer_context():
                _record(buf, "inner_1")
            _record(buf, "outer_2")
        buf.flush_sync()
        assert len(sink.events) == 3
        actions = [e.action for e in sink.events]
        assert "outer_1" in actions and "inner_1" in actions and "outer_2" in actions

    def test_multiple_streams_in_one_context(self) -> None:
        sink1, sink2 = _Sink(), _Sink()
        buf1, buf2 = _make_buf(sink1), _make_buf(sink2)
        with defer_context():
            _record(buf1, "s1_a")
            _record(buf2, "s2_a")
            _record(buf1, "s1_b")
        buf1.flush_sync()
        buf2.flush_sync()
        assert len(sink1.events) == 2
        assert len(sink2.events) == 1

    def test_try_defer_returns_false_outside_context(self) -> None:
        sink = _Sink()
        buf = _make_buf(sink)
        event = buf.record("x", principal=_P, resource="r")
        # Outside any defer context, _try_defer should return False
        assert not _try_defer(buf, event)

    def test_flush_deferred_suppresses_errors(self) -> None:
        # _flush_deferred should not propagate exceptions from failing streams
        class _ErrStream(_Sink):
            def emit(self, event: AuditEvent) -> None:
                raise RuntimeError("emit failed")

        err_stream = _ErrStream()
        sink = _Sink()
        buf = _make_buf(sink)
        event = buf.record("x", principal=_P, resource="r")
        # Call _flush_deferred directly with a failing stream
        _flush_deferred([(err_stream, event)])  # should not raise


# ---------------------------------------------------------------------------
# async_defer_context
# ---------------------------------------------------------------------------


class TestAsyncDeferContext:
    def test_basic_async_defer(self) -> None:
        sink = _Sink()
        buf = _make_buf(sink)

        async def _run() -> None:
            async with async_defer_context():
                _record(buf, "async_a")
                _record(buf, "async_b")
                assert len(sink.events) == 0

        asyncio.run(_run())
        buf.flush_sync()
        assert len(sink.events) == 2

    def test_async_defer_drop_on_exception(self) -> None:
        sink = _Sink()
        buf = _make_buf(sink)

        async def _run() -> None:
            with pytest.raises(RuntimeError):
                async with async_defer_context(on_error=ErrorPolicy.DROP):
                    _record(buf, "gone")
                    raise RuntimeError("boom")

        asyncio.run(_run())
        buf.flush_sync()
        assert len(sink.events) == 0

    def test_async_defer_flush_on_exception_non_drop(self) -> None:
        sink = _Sink()
        buf = _make_buf(sink)

        async def _run() -> None:
            with pytest.raises(ValueError):
                async with async_defer_context(on_error=ErrorPolicy.PANIC):
                    _record(buf, "kept")
                    raise ValueError("oops")

        asyncio.run(_run())
        buf.flush_sync()
        assert len(sink.events) == 1

    def test_async_nested_defer_merges(self) -> None:
        sink = _Sink()
        buf = _make_buf(sink)

        async def _run() -> None:
            async with async_defer_context():
                _record(buf, "outer")
                async with async_defer_context():
                    _record(buf, "inner")

        asyncio.run(_run())
        buf.flush_sync()
        assert len(sink.events) == 2
