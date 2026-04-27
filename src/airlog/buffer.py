"""Buffered and deferred audit stream output.

:class:`BufferedStream` wraps any :class:`~airlog.interfaces.AuditStream`
backend, staging events in an in-memory buffer and flushing them to the
backend in batches.  Backends remain **unchanged** – all buffering logic
lives in this middleware layer.

Flush triggers
--------------
* **Timer** – a daemon :class:`~threading.Timer` fires every
  *flush_interval* seconds (disabled when *flush_interval* is ``None``).
* **Size threshold** – when the buffer reaches *max_buffer_size* events or
  *max_buffer_bytes* bytes, a background flush is triggered immediately.
* **Manual** – call :meth:`~BufferedStream.flush_sync` (blocking) or
  :meth:`~BufferedStream.flush` (async-friendly).
* **atexit** – a final :meth:`~BufferedStream.flush_sync` is registered so
  events are not lost on normal interpreter shutdown.

Write-ahead log (WAL)
---------------------
When *wal_path* is provided, each accepted event is written to a SQLite
WAL table **before** entering the in-memory buffer.  On startup (or after a
crash) any unflushed WAL entries are replayed automatically, giving
crash-recovery durability with no external dependencies.

:class:`BatchEnvelope` wraps the ordered list of events emitted in a single
flush.  Its :meth:`~BatchEnvelope.verify` method recomputes the batch
checksum to detect gaps or reordering, enabling end-to-end gap detection.

:func:`flush_all` drains every live :class:`BufferedStream` registered in
the current process, which is useful in test teardown or shutdown hooks.

Example::

    from airlog.buffer import BufferedStream, ErrorPolicy, flush_all

    stream = BufferedStream(
        backend,
        flush_interval=5.0,
        max_buffer_size=1_000,
        error_policy=ErrorPolicy.RETRY,
        wal_path="/var/log/airlog.wal",
    )
    stream.record("login", principal=p, resource="session")
    stream.flush_sync()  # manual drain
    flush_all()          # drain all registered buffers
"""

from __future__ import annotations

import atexit
import contextlib
import hashlib
import json
import sqlite3
import threading
import time
import uuid
import warnings
import weakref
from dataclasses import dataclass
from enum import Enum, auto
from typing import Any

from airlog.interfaces import AuditEvent, AuditStream, HealthStatus, Principal, StreamFeature

__all__ = [
    "BatchEnvelope",
    "BufferHealth",
    "BufferStatus",
    "BufferedStream",
    "ErrorPolicy",
    "flush_all",
]

# ---------------------------------------------------------------------------
# Global weak-reference registry for flush_all()
# ---------------------------------------------------------------------------

_BUFFERS: list[weakref.ref[BufferedStream]] = []
_BUFFERS_LOCK = threading.Lock()


def _register_buffer(buf: BufferedStream) -> None:
    """Add *buf* to the process-wide registry consulted by :func:`flush_all`."""
    with _BUFFERS_LOCK:
        _BUFFERS.append(weakref.ref(buf))


# ---------------------------------------------------------------------------
# ErrorPolicy
# ---------------------------------------------------------------------------


class ErrorPolicy(Enum):
    """Action to take when the buffer is at capacity or a flush fails.

    Members
    -------
    RETRY:
        Flush the buffer synchronously and retry inserting the event up to
        three times.  On exhaustion the event is dropped with a
        :class:`RuntimeWarning`.
    DROP:
        Silently discard the overflowing event and emit a
        :class:`RuntimeWarning`.
    DEAD_LETTER:
        Forward the overflowing event to *dead_letter_backend* (if
        configured).  Falls back to ``DROP`` behaviour when no dead-letter
        backend is set.
    PANIC:
        Raise :exc:`RuntimeError` immediately.  Useful in tests to surface
        buffer pressure as a hard failure rather than a silent warning.
    """

    RETRY = auto()
    DROP = auto()
    DEAD_LETTER = auto()
    PANIC = auto()


# ---------------------------------------------------------------------------
# BufferStatus / BufferHealth
# ---------------------------------------------------------------------------


class BufferStatus(Enum):
    """Qualitative fill level of a :class:`BufferedStream`.

    Members
    -------
    OK:
        Buffer is below the warning threshold (80 %).
    WARNING:
        Buffer is at or above 80 % capacity.  An alert event is emitted
        through *alert_backend* if one is configured.
    BLOCKING:
        Buffer is completely full.  New events are handled according to the
        configured :class:`ErrorPolicy`.
    """

    OK = auto()
    WARNING = auto()
    BLOCKING = auto()


@dataclass
class BufferHealth:
    """Snapshot of :class:`BufferedStream` fill state.

    Attributes:
        event_count: Number of events currently staged in the in-memory
            buffer.
        pct_full: Buffer fill ratio in the range ``[0.0, 1.0]``.  The ratio
            is the maximum of the size-fill and the byte-fill so that either
            limit can trigger a warning.
        status: Qualitative status derived from *pct_full*.
    """

    event_count: int
    pct_full: float
    status: BufferStatus


# ---------------------------------------------------------------------------
# BatchEnvelope
# ---------------------------------------------------------------------------


@dataclass
class BatchEnvelope:
    """Multi-event flush wrapper with gap-detection capabilities.

    Instances should be created via :meth:`from_events`; do not construct
    directly.

    Attributes:
        batch_id: RFC-4122 UUID v4 string identifying this batch.
        first_seq: Lowest event sequence number in this batch.
        last_seq: Highest event sequence number in this batch.
        event_count: Number of events in :attr:`events`.
        batch_checksum: SHA-256 hex digest computed over the concatenated
            per-event :attr:`~airlog.interfaces.AuditEvent.checksum` values
            in list order.
        events: Ordered list of :class:`~airlog.interfaces.AuditEvent`
            objects belonging to this batch.
    """

    batch_id: str
    first_seq: int
    last_seq: int
    event_count: int
    batch_checksum: str
    events: list[AuditEvent]

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    def from_events(cls, events: list[AuditEvent]) -> BatchEnvelope:
        """Build a :class:`BatchEnvelope` from a non-empty list of events.

        Args:
            events: The events to wrap.  Must not be empty.

        Returns:
            A new :class:`BatchEnvelope` with all metadata computed.

        Raises:
            ValueError: If *events* is empty.
        """
        if not events:
            raise ValueError("Cannot create BatchEnvelope from an empty event list.")
        seqs = [e.sequence for e in events]
        batch_checksum = hashlib.sha256(
            "".join(e.checksum for e in events).encode()
        ).hexdigest()
        return cls(
            batch_id=str(uuid.uuid4()),
            first_seq=min(seqs),
            last_seq=max(seqs),
            event_count=len(events),
            batch_checksum=batch_checksum,
            events=list(events),
        )

    # ------------------------------------------------------------------
    # Serialization / verification
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable representation of this envelope.

        Returns:
            A plain Python :class:`dict` suitable for :func:`json.dumps`.
        """
        return {
            "batch_id": self.batch_id,
            "first_seq": self.first_seq,
            "last_seq": self.last_seq,
            "event_count": self.event_count,
            "batch_checksum": self.batch_checksum,
            "events": [e._as_dict() for e in self.events],
        }

    def verify(self) -> bool:
        """Return ``True`` if this envelope is internally consistent.

        Checks performed:

        * The batch checksum matches the recomputed value over the event
          checksums in list order.
        * :attr:`event_count` equals ``len(events)``.
        * :attr:`first_seq` and :attr:`last_seq` match the actual min/max
          sequence numbers in :attr:`events`.

        Returns:
            ``True`` when all checks pass, ``False`` on any mismatch.
        """
        if not self.events:
            return False
        if self.event_count != len(self.events):
            return False
        seqs = [e.sequence for e in self.events]
        if min(seqs) != self.first_seq or max(seqs) != self.last_seq:
            return False
        expected = hashlib.sha256(
            "".join(e.checksum for e in self.events).encode()
        ).hexdigest()
        return expected == self.batch_checksum


# ---------------------------------------------------------------------------
# BufferedStream
# ---------------------------------------------------------------------------


class BufferedStream(AuditStream):
    """An :class:`~airlog.interfaces.AuditStream` wrapper that stages events
    in memory and flushes them to a backend in batches.

    Args:
        backend: The downstream :class:`~airlog.interfaces.AuditStream` that
            receives flushed batches.
        flush_interval: Seconds between automatic timer-based flushes.
            ``None`` disables the timer (manual or threshold flushing only).
        max_buffer_size: Maximum number of events held in memory before a
            background flush is triggered.
        max_buffer_bytes: Maximum combined serialised size (bytes) of
            buffered events.  Events that would exceed this limit are handled
            according to *error_policy*.
        error_policy: Behaviour when the buffer is at capacity or a flush
            fails.  See :class:`ErrorPolicy`.
        wal_path: Filesystem path for the SQLite WAL database.  ``None``
            disables WAL (no crash recovery).
        alert_backend: Optional stream that receives a synthetic
            ``"buffer_warning"`` event when fill reaches 80 %.
        dead_letter_backend: Destination for events that cannot be accepted
            when *error_policy* is :attr:`ErrorPolicy.DEAD_LETTER`.
    """

    _WARNING_THRESHOLD: float = 0.80
    _RETRY_ATTEMPTS: int = 3
    _RETRY_SLEEP_S: float = 0.1

    def __init__(
        self,
        backend: AuditStream,
        *,
        flush_interval: float | None = 5.0,
        max_buffer_size: int = 1000,
        max_buffer_bytes: int = 10 * 1024 * 1024,
        error_policy: ErrorPolicy = ErrorPolicy.DROP,
        wal_path: str | None = None,
        alert_backend: AuditStream | None = None,
        dead_letter_backend: AuditStream | None = None,
    ) -> None:
        super().__init__()
        self._backend = backend
        self._flush_interval = flush_interval
        self._max_buffer_size = max_buffer_size
        self._max_buffer_bytes = max_buffer_bytes
        self._error_policy = error_policy
        self._alert_backend = alert_backend
        self._dead_letter_backend = dead_letter_backend

        # In-memory buffer: each entry is (wal_row_id | None, event)
        self._buffer: list[tuple[int | None, AuditEvent]] = []
        self._buffer_bytes: int = 0
        self._buffer_lock = threading.Lock()

        # WAL
        self._wal_conn: sqlite3.Connection | None = None
        self._wal_lock = threading.Lock()
        if wal_path is not None:
            self._init_wal(wal_path)
            self._replay_wal()

        # Timer
        self._timer: threading.Timer | None = None
        self._stopped = False
        if flush_interval is not None:
            self._schedule_timer()

        # Register for flush_all() and atexit
        _register_buffer(self)
        atexit.register(self._atexit_flush)

    # ------------------------------------------------------------------
    # WAL helpers
    # ------------------------------------------------------------------

    def _init_wal(self, path: str) -> None:
        """Open (or create) the SQLite WAL database at *path*."""
        conn = sqlite3.connect(path, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS wal_events (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                event_json TEXT    NOT NULL,
                created_at REAL    NOT NULL
            )
            """
        )
        conn.commit()
        self._wal_conn = conn

    def _replay_wal(self) -> None:
        """Load unflushed WAL entries into the in-memory buffer on startup."""
        if self._wal_conn is None:
            return
        with self._wal_lock:
            cursor = self._wal_conn.execute(
                "SELECT id, event_json FROM wal_events ORDER BY id"
            )
            rows: list[tuple[int, str]] = cursor.fetchall()

        for wal_id, event_json in rows:
            try:
                event = _deserialize_event(event_json)
            except Exception:  # corrupt WAL entry - skip
                self._wal_delete([wal_id])
                continue
            size = len(event_json.encode())
            with self._buffer_lock:
                self._buffer.append((wal_id, event))
                self._buffer_bytes += size

    def _wal_write(self, event: AuditEvent) -> int | None:
        """Persist *event* to the WAL; return the row ID or ``None``."""
        if self._wal_conn is None:
            return None
        event_json = json.dumps(event._as_dict(), default=str)
        with self._wal_lock:
            cursor = self._wal_conn.execute(
                "INSERT INTO wal_events (event_json, created_at) VALUES (?, ?)",
                (event_json, time.time()),
            )
            self._wal_conn.commit()
            return int(cursor.lastrowid)  # type: ignore[arg-type]

    def _wal_delete(self, wal_ids: list[int]) -> None:
        """Remove rows identified by *wal_ids* from the WAL."""
        if self._wal_conn is None or not wal_ids:
            return
        with self._wal_lock:
            self._wal_conn.executemany(
                "DELETE FROM wal_events WHERE id = ?",
                [(wid,) for wid in wal_ids],
            )
            self._wal_conn.commit()

    # ------------------------------------------------------------------
    # AuditStream.emit
    # ------------------------------------------------------------------

    def emit(self, event: AuditEvent) -> None:
        """Stage *event* in the buffer (writing to WAL first when configured).

        If a :func:`~airlog.defer.defer_context` is active in the current
        thread or coroutine, the event is captured by the defer context and
        forwarded to this stream only when the outermost defer context exits.

        Args:
            event: The audit event to buffer.
        """
        from airlog.defer import _try_defer  # lazy import avoids circular dep

        if _try_defer(self, event):
            return
        self._buffer_event(event)

    def _buffer_event(self, event: AuditEvent) -> None:
        """Write *event* to WAL then stage it in the in-memory buffer.

        This is the inner path called by :meth:`emit` (after the defer-context
        check) and by :func:`~airlog.defer._flush_deferred` when a deferred
        context exits.
        """
        estimated_bytes = len(json.dumps(event._as_dict(), default=str).encode())
        wal_id = self._wal_write(event)

        with self._buffer_lock:
            is_full = (
                len(self._buffer) >= self._max_buffer_size
                or self._buffer_bytes + estimated_bytes > self._max_buffer_bytes
            )
            if not is_full:
                self._buffer.append((wal_id, event))
                self._buffer_bytes += estimated_bytes
                current_count = len(self._buffer)
                pct = (
                    current_count / self._max_buffer_size
                    if self._max_buffer_size > 0
                    else 0.0
                )
                needs_flush = current_count >= self._max_buffer_size
                needs_alert = pct >= self._WARNING_THRESHOLD
            else:
                needs_flush = False
                needs_alert = False
                pct = 1.0

        if is_full:
            # Undo WAL write - event will not be buffered
            if wal_id is not None:
                self._wal_delete([wal_id])
            self._handle_overflow(event, estimated_bytes)
            return

        if needs_alert:
            self._emit_alert(pct)
        if needs_flush:
            threading.Thread(
                target=self.flush_sync, daemon=True, name="airlog-flush"
            ).start()

    # ------------------------------------------------------------------
    # Overflow / error handling
    # ------------------------------------------------------------------

    def _handle_overflow(self, event: AuditEvent, estimated_bytes: int) -> None:
        """Apply *error_policy* when the buffer cannot accept *event*."""
        match self._error_policy:
            case ErrorPolicy.DROP:
                warnings.warn(
                    f"airlog BufferedStream: buffer full - dropping event {event.event_id!r}",
                    RuntimeWarning,
                    stacklevel=5,
                )
            case ErrorPolicy.RETRY:
                self._retry_buffer(event, estimated_bytes)
            case ErrorPolicy.DEAD_LETTER:
                self._send_dead_letter(event)
            case ErrorPolicy.PANIC:
                raise RuntimeError(
                    f"airlog BufferedStream: buffer full "
                    f"(max_size={self._max_buffer_size}, "
                    f"max_bytes={self._max_buffer_bytes}) - "
                    f"cannot accept event {event.event_id!r}"
                )

    def _retry_buffer(self, event: AuditEvent, estimated_bytes: int) -> None:
        """Flush and retry buffering *event* up to :attr:`_RETRY_ATTEMPTS` times."""
        for _ in range(self._RETRY_ATTEMPTS):
            time.sleep(self._RETRY_SLEEP_S)
            self.flush_sync()
            wal_id = self._wal_write(event)
            with self._buffer_lock:
                fits = (
                    len(self._buffer) < self._max_buffer_size
                    and self._buffer_bytes + estimated_bytes <= self._max_buffer_bytes
                )
                if fits:
                    self._buffer.append((wal_id, event))
                    self._buffer_bytes += estimated_bytes
                    return
            # Did not fit - remove the provisional WAL entry
            if wal_id is not None:
                self._wal_delete([wal_id])

        warnings.warn(
            f"airlog BufferedStream: retry exhausted - dropping event {event.event_id!r}",
            RuntimeWarning,
            stacklevel=5,
        )

    def _send_dead_letter(self, event: AuditEvent) -> None:
        """Forward *event* to the dead-letter backend (best-effort)."""
        if self._dead_letter_backend is not None:
            with contextlib.suppress(Exception):
                self._dead_letter_backend.emit(event)
        else:
            warnings.warn(
                "airlog BufferedStream: DEAD_LETTER policy active but no "
                "dead_letter_backend configured - dropping event.",
                RuntimeWarning,
                stacklevel=5,
            )

    def _emit_alert(self, pct_full: float) -> None:
        """Send a ``"buffer_warning"`` event through *alert_backend* (best-effort)."""
        if self._alert_backend is None:
            return
        alert_principal = Principal(subject="airlog.buffer", auth_method="system")
        with contextlib.suppress(Exception):
            self._alert_backend.record(
                "buffer_warning",
                principal=alert_principal,
                resource="airlog.BufferedStream",
                outcome="warning",
                context={
                    "pct_full": round(pct_full, 4),
                    "event_count": len(self._buffer),
                    "max_buffer_size": self._max_buffer_size,
                },
            )

    def _handle_flush_failure(
        self,
        batch: list[tuple[int | None, AuditEvent]],
        wal_ids: list[int],
        exc: Exception,
    ) -> None:
        """Dispose of a failed *batch* according to *error_policy*."""
        match self._error_policy:
            case ErrorPolicy.RETRY:
                # Return events to the front of the buffer for the next flush
                with self._buffer_lock:
                    self._buffer = batch + self._buffer
                    self._buffer_bytes = sum(
                        len(json.dumps(evt._as_dict(), default=str).encode())
                        for _, evt in self._buffer
                    )
                # WAL entries are kept - they back the re-buffered events
            case ErrorPolicy.DEAD_LETTER:
                self._wal_delete(wal_ids)
                for _, evt in batch:
                    self._send_dead_letter(evt)
            case ErrorPolicy.PANIC:
                raise exc
            case ErrorPolicy.DROP:
                self._wal_delete(wal_ids)
                warnings.warn(
                    f"airlog BufferedStream: flush failed, dropping {len(batch)} event(s): {exc}",
                    RuntimeWarning,
                    stacklevel=3,
                )

    # ------------------------------------------------------------------
    # Flush
    # ------------------------------------------------------------------

    def flush_sync(self) -> None:
        """Drain the in-memory buffer and emit all events to the backend.

        Blocks until every event in the current batch has been accepted by
        the backend.  On flush failure the :class:`ErrorPolicy` is applied
        to the entire batch.

        This method is thread-safe and idempotent – concurrent calls will
        each drain a disjoint snapshot of the buffer.
        """
        with self._buffer_lock:
            if not self._buffer:
                return
            batch = list(self._buffer)
            self._buffer.clear()
            self._buffer_bytes = 0

        wal_ids = [wid for wid, _ in batch if wid is not None]
        events = [evt for _, evt in batch]
        envelope = BatchEnvelope.from_events(events)

        try:
            for evt in envelope.events:
                self._backend.emit(evt)
            self._wal_delete(wal_ids)
        except Exception as exc:
            self._handle_flush_failure(batch, wal_ids, exc)

    async def flush(self) -> None:
        """Async-friendly wrapper around :meth:`flush_sync`.

        Runs the synchronous flush in a thread pool via
        :func:`asyncio.to_thread` so it does not block the event loop.
        """
        import asyncio

        await asyncio.to_thread(self.flush_sync)

    # ------------------------------------------------------------------
    # Health / monitoring
    # ------------------------------------------------------------------

    def buffer_health(self) -> BufferHealth:
        """Return a snapshot of the current buffer fill state.

        The :attr:`~BufferHealth.pct_full` is the maximum of the event-count
        and byte-count fill ratios so that either limit can trigger a warning.

        Returns:
            A :class:`BufferHealth` instance.
        """
        with self._buffer_lock:
            count = len(self._buffer)
            byte_count = self._buffer_bytes

        size_pct = count / self._max_buffer_size if self._max_buffer_size > 0 else 0.0
        byte_pct = (
            byte_count / self._max_buffer_bytes if self._max_buffer_bytes > 0 else 0.0
        )
        pct = min(max(size_pct, byte_pct), 1.0)

        if pct >= 1.0:
            status = BufferStatus.BLOCKING
        elif pct >= self._WARNING_THRESHOLD:
            status = BufferStatus.WARNING
        else:
            status = BufferStatus.OK

        return BufferHealth(event_count=count, pct_full=pct, status=status)

    def health_check(self) -> HealthStatus:
        """Aggregate backend health with buffer fill state.

        Returns:
            A :class:`~airlog.interfaces.HealthStatus` that is unhealthy
            when the backend is unhealthy **or** the buffer is
            :attr:`BufferStatus.BLOCKING`.
        """
        backend_health = self._backend.health_check()
        buf_health = self.buffer_health()
        msg = (
            f"buffer={buf_health.pct_full:.0%} full "
            f"({buf_health.event_count}/{self._max_buffer_size}); "
            f"backend: {backend_health.message}"
        )
        is_healthy = backend_health.healthy and buf_health.status is not BufferStatus.BLOCKING
        return HealthStatus(
            healthy=is_healthy,
            latency_ms=backend_health.latency_ms,
            message=msg,
        )

    def supports_feature(self, feature: StreamFeature) -> bool:
        """Return ``True`` for :attr:`~StreamFeature.BATCHING`; delegate others.

        Args:
            feature: The capability to query.

        Returns:
            ``True`` when the feature is supported.
        """
        if feature is StreamFeature.BATCHING:
            return True
        return self._backend.supports_feature(feature)

    # ------------------------------------------------------------------
    # Lifecycle / timer
    # ------------------------------------------------------------------

    def _schedule_timer(self) -> None:
        """Schedule the next periodic flush timer."""
        if self._stopped or self._flush_interval is None:
            return
        self._timer = threading.Timer(self._flush_interval, self._timer_callback)
        self._timer.daemon = True
        self._timer.start()

    def _timer_callback(self) -> None:
        """Flush then reschedule (called by the daemon timer thread)."""
        try:
            self.flush_sync()
        finally:
            self._schedule_timer()

    def _atexit_flush(self) -> None:
        """Best-effort flush registered with :func:`atexit`."""
        with contextlib.suppress(Exception):
            self.stop()

    def stop(self) -> None:
        """Cancel the flush timer and perform a final synchronous flush.

        After :meth:`stop` is called the timer will not reschedule.  This
        method is idempotent – subsequent calls are no-ops.
        """
        self._stopped = True
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None
        self.flush_sync()
        if self._wal_conn is not None:
            with contextlib.suppress(Exception):
                self._wal_conn.close()
            self._wal_conn = None


# ---------------------------------------------------------------------------
# flush_all
# ---------------------------------------------------------------------------


def flush_all() -> None:
    """Flush every live :class:`BufferedStream` registered in this process.

    Dead (garbage-collected) entries are silently skipped.  Errors from
    individual streams are swallowed so that one unhealthy stream does not
    prevent others from flushing.

    This function is safe to call from any thread, including an
    :func:`atexit` handler.
    """
    with _BUFFERS_LOCK:
        refs = list(_BUFFERS)
    for ref in refs:
        buf = ref()
        if buf is None:
            continue
        with contextlib.suppress(Exception):
            buf.flush_sync()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _deserialize_event(event_json: str) -> AuditEvent:
    """Reconstruct an :class:`~airlog.interfaces.AuditEvent` from WAL JSON.

    Args:
        event_json: The JSON string stored in the WAL table.

    Returns:
        A fully populated :class:`~airlog.interfaces.AuditEvent`.

    Raises:
        KeyError: If a required field is missing from the stored JSON.
        json.JSONDecodeError: If *event_json* is not valid JSON.
    """
    data: dict[str, Any] = json.loads(event_json)
    pd: dict[str, Any] = data["principal"]
    principal = Principal(
        subject=str(pd["subject"]),
        auth_method=str(pd["auth_method"]),
        metadata={str(k): str(v) for k, v in pd.get("metadata", {}).items()},
    )
    return AuditEvent(
        event_id=str(data["event_id"]),
        sequence=int(data["sequence"]),
        timestamp_ns=int(data["timestamp_ns"]),
        action=str(data["action"]),
        principal=principal,
        resource=str(data["resource"]),
        resource_id=data.get("resource_id"),
        outcome=str(data.get("outcome", "success")),
        correlation_id=data.get("correlation_id"),
        context=dict(data.get("context", {})),
        checksum=str(data["checksum"]),
    )
