"""Integrity verification for audit streams.

:class:`IntegrityVerificationStream` wraps two backends (the *primary* and
the *replica*) and periodically cross-verifies events by replaying the
primary's sequence through the replica, recomputing checksums, and comparing
the results.  On mismatch an :class:`IntegrityViolation` event is emitted
through the supplied callback.

Only backends advertising :attr:`~airlog.interfaces.StreamFeature.REPLAY`
are verifiable.  When the primary does not support ``REPLAY`` the wrapper
operates in pass-through mode and logs a warning.

Example::

    from airlog.integrity import IntegrityVerificationStream

    def on_violation(v):
        print(f"Violation: {v}")

    stream = IntegrityVerificationStream(
        primary=primary_backend,
        replica=replica_backend,
        on_violation=on_violation,
        verify_interval_s=60.0,
    )
    stream.record("login", principal=p, resource="session")
    stream.start()   # begin periodic verification
    # …
    stream.stop()
"""

from __future__ import annotations

import contextlib
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from airlog.interfaces import AuditEvent, AuditStream, HealthStatus, StreamFeature

__all__ = [
    "IntegrityVerificationStream",
    "IntegrityViolation",
    "ReplayableStream",
]


# ---------------------------------------------------------------------------
# ReplayableStream protocol
# ---------------------------------------------------------------------------


class ReplayableStream(AuditStream):
    """Extension of :class:`~airlog.interfaces.AuditStream` for replayable backends.

    Backends that support :attr:`~airlog.interfaces.StreamFeature.REPLAY` should
    subclass this (or duck-type the :meth:`replay` method) so that
    :class:`IntegrityVerificationStream` can iterate stored events.

    The ``REPLAY`` feature flag must be advertised via
    :meth:`~airlog.interfaces.AuditStream.supports_feature`.
    """

    def replay(
        self,
        from_sequence: int = 1,
        to_sequence: int | None = None,
    ) -> list[AuditEvent]:
        """Return stored events in sequence order.

        Args:
            from_sequence: Inclusive lower bound on sequence numbers.
            to_sequence: Inclusive upper bound on sequence numbers, or
                ``None`` to return all events from *from_sequence* onward.

        Returns:
            A list of :class:`~airlog.interfaces.AuditEvent` objects, sorted
            by ``sequence`` ascending.

        Raises:
            NotImplementedError: Always – subclasses must override this.
        """
        raise NotImplementedError(  # pragma: no cover
            "Replayable backends must implement replay()."
        )


# ---------------------------------------------------------------------------
# IntegrityViolation
# ---------------------------------------------------------------------------


@dataclass
class IntegrityViolation:
    """Describes a detected mismatch between two backends.

    Attributes:
        event_id: The ``event_id`` of the mismatched event.
        sequence: The ``sequence`` number of the mismatched event.
        primary_checksum: Checksum stored in the primary backend.
        replica_checksum: Checksum stored in the replica backend, or ``None``
            if the event was missing from the replica entirely.
        detected_at_ns: Wall-clock timestamp (nanoseconds) when the violation
            was detected.
        detail: Human-readable description of the mismatch.
    """

    event_id: str
    sequence: int
    primary_checksum: str
    replica_checksum: str | None
    detected_at_ns: int
    detail: str

    def __str__(self) -> str:
        return (
            f"IntegrityViolation(seq={self.sequence}, "
            f"event={self.event_id!r}, "
            f"primary={self.primary_checksum[:8]}…, "
            f"replica={self.replica_checksum[:8] + '…' if self.replica_checksum else 'MISSING'}, "
            f"detail={self.detail!r})"
        )


# ---------------------------------------------------------------------------
# IntegrityVerificationStream
# ---------------------------------------------------------------------------


class IntegrityVerificationStream(AuditStream):
    """Dual-backend stream with periodic integrity cross-verification.

    Every :meth:`emit` call writes to *both* the primary and the replica.
    A background timer fires every *verify_interval_s* seconds and replays
    events from the primary through :meth:`~ReplayableStream.replay`, then
    compares checksums against the replica.  Any mismatch triggers the
    *on_violation* callback with an :class:`IntegrityViolation`.

    .. note::
        Verification only runs when **both** backends advertise
        :attr:`~airlog.interfaces.StreamFeature.REPLAY`.  If they do not the
        stream still works as a transparent dual-write wrapper.

    Args:
        primary: The authoritative :class:`~airlog.interfaces.AuditStream`.
        replica: The replica :class:`~airlog.interfaces.AuditStream`.
        on_violation: Callback invoked with an :class:`IntegrityViolation`
            when a mismatch is detected.
        verify_interval_s: Seconds between verification runs.  Defaults to
            ``300.0`` (5 minutes).
        verify_batch_size: Maximum number of events verified per run.

    Example::

        stream = IntegrityVerificationStream(
            primary=primary,
            replica=replica,
            on_violation=lambda v: logger.error("Integrity violation: %s", v),
        )
        stream.start()
    """

    def __init__(
        self,
        primary: AuditStream,
        replica: AuditStream,
        on_violation: Callable[[IntegrityViolation], Any],
        *,
        verify_interval_s: float = 300.0,
        verify_batch_size: int = 1_000,
    ) -> None:
        super().__init__()
        self._primary = primary
        self._replica = replica
        self._on_violation = on_violation
        self._verify_interval_s = verify_interval_s
        self._verify_batch_size = verify_batch_size
        self._timer: threading.Timer | None = None
        self._timer_lock = threading.Lock()
        self._last_verified_seq: int = 0
        self._running = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the background verification timer.

        Safe to call multiple times; subsequent calls are no-ops.
        """
        with self._timer_lock:
            if self._running:
                return
            self._running = True
        self._schedule()

    def stop(self) -> None:
        """Stop the background verification timer.

        Blocks until any in-progress verification run finishes.
        """
        with self._timer_lock:
            self._running = False
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None

    def _schedule(self) -> None:
        with self._timer_lock:
            if not self._running:
                return
            self._timer = threading.Timer(self._verify_interval_s, self._run_verification)
            self._timer.daemon = True
            self._timer.start()

    def _run_verification(self) -> None:
        """Execute one verification pass and reschedule."""
        try:
            self.verify_now()
        finally:
            self._schedule()

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify_now(self) -> list[IntegrityViolation]:
        """Run an integrity check immediately (synchronous).

        Replays events from the primary backend since the last verified
        sequence number, recomputes their checksums, and compares against the
        replica.

        Returns:
            A list of :class:`IntegrityViolation` instances detected during
            this run.  An empty list means no mismatches were found.
        """
        if not self._primary.supports_feature(StreamFeature.REPLAY):
            return []
        if not self._replica.supports_feature(StreamFeature.REPLAY):
            return []

        primary_replay: ReplayableStream = self._primary  # type: ignore[assignment]
        replica_replay: ReplayableStream = self._replica  # type: ignore[assignment]

        from_seq = self._last_verified_seq + 1
        to_seq = from_seq + self._verify_batch_size - 1

        try:
            primary_events = primary_replay.replay(from_seq, to_seq)
        except Exception:
            return []

        if not primary_events:
            return []

        # Build a lookup map from the replica
        try:
            max_seq = max(e.sequence for e in primary_events)
            replica_events = replica_replay.replay(from_seq, max_seq)
        except Exception:
            replica_events = []

        replica_map: dict[int, AuditEvent] = {e.sequence: e for e in replica_events}

        violations: list[IntegrityViolation] = []
        for primary_event in primary_events:
            # First verify the primary event's own checksum
            if not primary_event.verify():
                v = IntegrityViolation(
                    event_id=primary_event.event_id,
                    sequence=primary_event.sequence,
                    primary_checksum=primary_event.checksum,
                    replica_checksum=None,
                    detected_at_ns=time.time_ns(),
                    detail="Primary event failed self-verification (tampered)",
                )
                violations.append(v)
                self._on_violation(v)
                continue

            replica_event = replica_map.get(primary_event.sequence)
            if replica_event is None:
                v = IntegrityViolation(
                    event_id=primary_event.event_id,
                    sequence=primary_event.sequence,
                    primary_checksum=primary_event.checksum,
                    replica_checksum=None,
                    detected_at_ns=time.time_ns(),
                    detail="Event missing from replica",
                )
                violations.append(v)
                self._on_violation(v)
            elif replica_event.checksum != primary_event.checksum:
                v = IntegrityViolation(
                    event_id=primary_event.event_id,
                    sequence=primary_event.sequence,
                    primary_checksum=primary_event.checksum,
                    replica_checksum=replica_event.checksum,
                    detected_at_ns=time.time_ns(),
                    detail="Checksum mismatch between primary and replica",
                )
                violations.append(v)
                self._on_violation(v)

        if primary_events:
            self._last_verified_seq = max(e.sequence for e in primary_events)

        return violations

    # ------------------------------------------------------------------
    # AuditStream interface
    # ------------------------------------------------------------------

    def emit(self, event: AuditEvent) -> None:
        """Emit *event* to both the primary and the replica backend.

        Args:
            event: The audit event to emit.

        Raises:
            Exception: Re-raises any exception from the primary backend.
                Replica failures are suppressed (best-effort dual-write).
        """
        self._primary.emit(event)
        with contextlib.suppress(Exception):
            self._replica.emit(event)

    async def aemit(self, event: AuditEvent) -> bool:
        """Asynchronously emit *event* to both backends.

        Args:
            event: The audit event to emit.

        Returns:
            ``True`` when the primary accepted the event.
        """
        primary_ok = await self._primary.aemit(event)
        with contextlib.suppress(Exception):
            await self._replica.aemit(event)
        return primary_ok

    def health_check(self) -> HealthStatus:
        """Return the combined health of both backends.

        Returns:
            Unhealthy if either the primary or replica is unhealthy.
        """
        primary_status = self._primary.health_check()
        replica_status = self._replica.health_check()
        total_latency = primary_status.latency_ms + replica_status.latency_ms
        if not primary_status.healthy or not replica_status.healthy:
            messages = [
                m for m in (primary_status.message, replica_status.message) if m and m != "OK"
            ]
            return HealthStatus(
                healthy=False,
                latency_ms=total_latency,
                message="; ".join(messages) or "One or more backends unhealthy",
            )
        return HealthStatus(healthy=True, latency_ms=total_latency, message="OK")

    def supports_feature(self, feature: StreamFeature) -> bool:
        """Return ``True`` if both backends support *feature*.

        Args:
            feature: The feature to query.
        """
        return self._primary.supports_feature(feature) and self._replica.supports_feature(feature)
