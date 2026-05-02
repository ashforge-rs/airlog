"""Interfaces and core data types for audit logging.

Highlights
----------
- :class:`Principal` – authenticated entity (user, API key, certificate …)
- :class:`AuditEvent` – immutable, integrity-checked audit record with
  nanosecond timestamps, sequence numbers, correlation IDs, and a SHA-256
  checksum for tamper detection.
- :class:`AuditStream` – append-only stream ABC with a thread-safe sequence
  counter; concrete back-ends implement only :meth:`~AuditStream.emit`.
- :class:`HealthStatus` – health-check result returned by
  :meth:`~AuditStream.health_check`.
- :class:`StreamFeature` – capability flags queried via
  :meth:`~AuditStream.supports_feature`.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import threading
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum, auto
from typing import Any

from airlog.ocsf_support import OcsfClass, OcsfSeverity, build_ocsf_event
from airlog.serialization import SerializationFormat

__all__ = [
    "AuditEvent",
    "AuditStream",
    "HealthStatus",
    "Principal",
    "SerializationFormat",
    "StreamFeature",
]

# ---------------------------------------------------------------------------
# StreamFeature
# ---------------------------------------------------------------------------


class StreamFeature(Enum):
    """Optional capability flags that a backend stream may advertise.

    Use :meth:`~AuditStream.supports_feature` to query whether a concrete
    stream supports a given feature.

    Members
    -------
    QUERY:
        The backend supports structured querying of past events.
    REPLAY:
        The backend can replay a historical event sequence.
    RETENTION:
        The backend enforces a configurable retention / expiry policy.
    BATCHING:
        The backend coalesces multiple :meth:`~AuditStream.emit` calls into
        bulk writes for efficiency.
    ASYNC:
        The backend has a native async implementation and does not merely
        wrap :meth:`~AuditStream.emit` in :func:`asyncio.to_thread`.
    """

    QUERY = auto()
    REPLAY = auto()
    RETENTION = auto()
    BATCHING = auto()
    ASYNC = auto()


# ---------------------------------------------------------------------------
# HealthStatus
# ---------------------------------------------------------------------------


@dataclass
class HealthStatus:
    """Result of :meth:`~AuditStream.health_check`.

    Args:
        healthy: ``True`` when the stream is fully operational.
        latency_ms: Round-trip time in milliseconds measured during the check.
        message: Optional human-readable description of the current status or
            any error encountered.
    """

    healthy: bool
    latency_ms: float
    message: str = ""


# ---------------------------------------------------------------------------
# Principal
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Principal:
    """Authenticated entity that performed an audited action.

    Args:
        subject: Stable, unique identifier for the principal – e.g. a user ID,
            the SHA-256 fingerprint of an API key, or a TLS certificate
            subject DN.
        auth_method: How the principal was authenticated.  Recommended values:
            ``"password"``, ``"api_key"``, ``"certificate"``, ``"jwt"``,
            ``"oauth2"``, ``"saml"``.
        metadata: Optional bag of string key/value pairs for extra context
            (role, IP address, tenant ID, …).  Stored but not used for
            checksum computation to allow enrichment without invalidating
            existing records.
    """

    subject: str
    auth_method: str
    metadata: dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# AuditEvent
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuditEvent:
    """Immutable, integrity-verified audit event.

    Do **not** construct instances directly – use :meth:`AuditStream.record`
    so that the sequence number and checksum are filled in correctly.

    Args:
        event_id: RFC-4122 UUID v4 string – globally unique per event.
        sequence: Monotonically increasing integer within the stream.  Can be
            used to detect gaps in the audit trail.
        timestamp_ns: Wall-clock time in **nanoseconds** since the Unix epoch.
        action: Operation that was performed (e.g. ``"create"``, ``"login"``,
            ``"export"``).
        principal: Authenticated identity that performed the action.
        resource: Kind of resource being acted upon (e.g. ``"document"``,
            ``"user_account"``).
        resource_id: Optional identifier of the specific resource instance.
        outcome: ``"success"`` or ``"failure"``.
        correlation_id: Optional ID shared by all events in the same
            request / session – enables end-to-end lifecycle tracing.
        context: Arbitrary supplemental key/value data (IP addresses, HTTP
            method, query parameters, …).
        checksum: SHA-256 hex digest over all fields except *metadata* and
            *checksum* itself.  Used to detect post-write tampering.
    """

    event_id: str
    sequence: int
    timestamp_ns: int
    action: str
    principal: Principal
    resource: str
    resource_id: str | None
    outcome: str
    correlation_id: str | None
    context: dict[str, Any]
    checksum: str

    # ------------------------------------------------------------------
    # Derived properties
    # ------------------------------------------------------------------

    @property
    def timestamp(self) -> datetime:
        """Return this event's timestamp as a timezone-aware UTC :class:`~datetime.datetime`.

        The value is recomputed from :attr:`timestamp_ns` on each access.
        If you need to read it more than once in a tight loop, assign it to a
        local variable first::

            ts = event.timestamp
        """
        return datetime.fromtimestamp(self.timestamp_ns / 1_000_000_000, tz=UTC)

    # ------------------------------------------------------------------
    # Integrity helpers
    # ------------------------------------------------------------------

    @classmethod
    def _compute_checksum(
        cls,
        event_id: str,
        sequence: int,
        timestamp_ns: int,
        action: str,
        principal: Principal,
        resource: str,
        resource_id: str | None,
        outcome: str,
        correlation_id: str | None,
        context: dict[str, Any],
    ) -> str:
        """Return the SHA-256 hex digest over the canonical JSON of the given fields.

        The *principal.metadata* field is intentionally excluded so that
        metadata enrichment (e.g. adding a ``"reviewed_by"`` key) does not
        invalidate the checksum of an already-stored event.
        """
        canonical = json.dumps(
            {
                "event_id": event_id,
                "sequence": sequence,
                "timestamp_ns": timestamp_ns,
                "action": action,
                "principal": {
                    "subject": principal.subject,
                    "auth_method": principal.auth_method,
                },
                "resource": resource,
                "resource_id": resource_id,
                "outcome": outcome,
                "correlation_id": correlation_id,
                "context": context,
            },
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(canonical.encode()).hexdigest()

    def verify(self) -> bool:
        """Return ``True`` if this event's checksum matches its field values.

        A ``False`` result indicates that the record has been tampered with
        after it was originally written to the stream.
        """
        expected = self._compute_checksum(
            event_id=self.event_id,
            sequence=self.sequence,
            timestamp_ns=self.timestamp_ns,
            action=self.action,
            principal=self.principal,
            resource=self.resource,
            resource_id=self.resource_id,
            outcome=self.outcome,
            correlation_id=self.correlation_id,
            context=self.context,
        )
        return expected == self.checksum

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def _as_dict(self) -> dict[str, Any]:
        """Return a plain JSON-serialisable dict of all event fields."""
        return {
            "event_id": self.event_id,
            "sequence": self.sequence,
            "timestamp_ns": self.timestamp_ns,
            "action": self.action,
            "principal": {
                "subject": self.principal.subject,
                "auth_method": self.principal.auth_method,
                "metadata": self.principal.metadata,
            },
            "resource": self.resource,
            "resource_id": self.resource_id,
            "outcome": self.outcome,
            "correlation_id": self.correlation_id,
            "context": self.context,
            "checksum": self.checksum,
        }

    def to_dict(
        self, fmt: SerializationFormat = SerializationFormat.JSON
    ) -> dict[str, Any] | bytes:
        """Serialize this event to a dictionary or encoded bytes.

        Args:
            fmt: Target serialization format.

                - :attr:`~SerializationFormat.JSON` *(default)* – returns a
                  plain Python :class:`dict` whose values are JSON-serialisable.
                  Pass the result to :func:`json.dumps` to obtain a JSON string.
                - :attr:`~SerializationFormat.MSGPACK` – returns ``bytes``
                  encoded with `msgpack <https://msgpack.org>`_.  Requires the
                  optional ``msgpack`` package.

        Returns:
            A :class:`dict` for ``JSON`` format, or ``bytes`` for ``MSGPACK``.

        Raises:
            ImportError: When *fmt* is ``MSGPACK`` and ``msgpack`` is not
                installed.
        """
        match fmt:
            case SerializationFormat.JSON:
                return self._as_dict()
            case SerializationFormat.MSGPACK:
                try:
                    import msgpack  # type: ignore[import-not-found]
                except ImportError as exc:
                    raise ImportError(
                        "The 'msgpack' package is required for MSGPACK serialization. "
                        "Install it with: pip install msgpack"
                    ) from exc
                return msgpack.packb(self._as_dict(), use_bin_type=True)

    def to_ocsf(
        self,
        ocsf_class: OcsfClass | None = None,
        severity_id: int = OcsfSeverity.INFORMATIONAL,
    ) -> dict[str, Any]:
        """Map this event to an OCSF-compliant event dictionary.

        The OCSF class is inferred from the action string by default:

        * Login/logout actions → **class 3002** (Authentication)
        * User/account lifecycle actions → **class 3001** (Account Change)
        * Everything else → **class 6003** (API Activity, the safe default)

        Override *ocsf_class* to force a specific class regardless of the
        action.

        Args:
            ocsf_class: Target :class:`~airlog.ocsf_support.OcsfClass`.
                ``None`` (default) auto-detects the class from the action.
            severity_id: OCSF ``severity_id`` integer.  Use
                :class:`~airlog.ocsf_support.OcsfSeverity` for named
                constants.  Defaults to ``1`` (Informational).

        Returns:
            A plain Python :class:`dict` conforming to OCSF schema 1.1.

        See Also:
            :func:`~airlog.ocsf_support.build_ocsf_event`,
            :func:`~airlog.ocsf_support.validate_ocsf_event`
        """
        return build_ocsf_event(self, ocsf_class=ocsf_class, severity_id=severity_id)


class AuditStream(ABC):
    """Abstract, append-only audit event stream.

    Concrete implementations override only :meth:`emit` and call
    ``super().__init__()`` in their own ``__init__``.  The base class manages
    the thread-safe sequence counter and event construction.

    Usage::

        class MyStream(AuditStream):
            def emit(self, event: AuditEvent) -> None:
                write_to_storage(event)

        stream = MyStream()
        event = stream.record(
            "login",
            principal=Principal(subject="alice", auth_method="password"),
            resource="session",
            correlation_id="req-abc123",
        )
        assert event.verify()
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sequence: int = 0

    def _next_sequence(self) -> int:
        """Atomically increment and return the next sequence number."""
        with self._lock:
            self._sequence += 1
            return self._sequence

    @abstractmethod
    def emit(self, event: AuditEvent) -> None:
        """Persist or forward *event*.

        Implementations **must** treat the stream as append-only: existing
        records must never be modified or deleted.

        Args:
            event: The fully constructed, integrity-signed audit event.
        """

    async def aemit(self, event: AuditEvent) -> bool:
        """Asynchronously emit *event*.

        The default implementation delegates to :meth:`emit` via
        :func:`asyncio.to_thread` so that synchronous backends remain
        non-blocking in an async context without any changes.

        Override this method (and advertise :attr:`~StreamFeature.ASYNC` via
        :meth:`supports_feature`) if the backend has a native async I/O path.

        Args:
            event: The fully constructed, integrity-signed audit event.

        Returns:
            ``True`` when the event was accepted by the backend.
        """
        await asyncio.to_thread(self.emit, event)
        return True

    def health_check(self) -> HealthStatus:
        """Return the current health of this stream.

        The default implementation performs a lightweight round-trip timing
        probe by measuring the time to acquire the sequence lock.  Override
        for backend-specific checks (e.g. testing a database connection).

        Returns:
            A :class:`HealthStatus` describing whether the stream is
            operational and how long the check took.
        """
        start = time.monotonic()
        try:
            with self._lock:
                pass
            latency_ms = (time.monotonic() - start) * 1_000
            return HealthStatus(healthy=True, latency_ms=latency_ms, message="OK")
        except Exception as exc:
            latency_ms = (time.monotonic() - start) * 1_000
            return HealthStatus(healthy=False, latency_ms=latency_ms, message=str(exc))

    def supports_feature(self, feature: StreamFeature) -> bool:
        """Return whether this stream supports *feature*.

        The default implementation returns ``False`` for all features.
        Override to advertise the capabilities of a concrete backend.

        Args:
            feature: The :class:`StreamFeature` to query.

        Returns:
            ``True`` if the feature is supported, ``False`` otherwise.
        """
        return False

    def record(
        self,
        action: str,
        principal: Principal,
        resource: str,
        *,
        resource_id: str | None = None,
        outcome: str = "success",
        correlation_id: str | None = None,
        **context: Any,
    ) -> AuditEvent:
        """Build an :class:`AuditEvent`, sign it, emit it, and return it.

        The returned event can be inspected for its ``event_id`` or
        ``checksum`` immediately after the call.

        Args:
            action: Operation that was performed.
            principal: Authenticated identity performing the action.
            resource: Kind of resource being acted upon.
            resource_id: Optional instance identifier.
            outcome: ``"success"`` (default) or ``"failure"``.
            correlation_id: Optional cross-event correlation token.
            **context: Arbitrary supplemental key/value data.

        Returns:
            The emitted :class:`AuditEvent`.
        """
        event_id = str(uuid.uuid4())
        sequence = self._next_sequence()
        timestamp_ns = time.time_ns()
        ctx: dict[str, Any] = dict(context)

        checksum = AuditEvent._compute_checksum(
            event_id=event_id,
            sequence=sequence,
            timestamp_ns=timestamp_ns,
            action=action,
            principal=principal,
            resource=resource,
            resource_id=resource_id,
            outcome=outcome,
            correlation_id=correlation_id,
            context=ctx,
        )

        event = AuditEvent(
            event_id=event_id,
            sequence=sequence,
            timestamp_ns=timestamp_ns,
            action=action,
            principal=principal,
            resource=resource,
            resource_id=resource_id,
            outcome=outcome,
            correlation_id=correlation_id,
            context=ctx,
            checksum=checksum,
        )
        self.emit(event)
        return event
