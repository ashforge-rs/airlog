"""Convenience re-exports for stream-related public API.

Import stream types from this module or directly from
:mod:`airlog.interfaces` – both paths are stable.

Example::

    from airlog.streams import AuditStream, HealthStatus, StreamFeature
"""

from __future__ import annotations

from airlog.interfaces import AuditEvent, AuditStream, HealthStatus, Principal, StreamFeature
from airlog.serialization import SerializationFormat

__all__ = [
    "AuditEvent",
    "AuditStream",
    "HealthStatus",
    "Principal",
    "SerializationFormat",
    "StreamFeature",
]
