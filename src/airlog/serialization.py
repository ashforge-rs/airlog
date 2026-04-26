"""Serialization helpers for :class:`~airlog.interfaces.AuditEvent`.

Provides :class:`SerializationFormat` for use with
:meth:`~airlog.interfaces.AuditEvent.to_dict`.
"""

from __future__ import annotations

from enum import Enum, auto

__all__ = ["SerializationFormat"]


class SerializationFormat(Enum):
    """Target format for :meth:`~airlog.interfaces.AuditEvent.to_dict`.

    Members
    -------
    JSON:
        Return a plain Python :class:`dict` whose values are JSON-serialisable.
        Pass the result to :func:`json.dumps` to obtain a JSON string.
    MSGPACK:
        Return ``bytes`` encoded with `msgpack <https://msgpack.org>`_.
        Requires the optional ``msgpack`` package.  Install it with::

            pip install msgpack
    """

    JSON = auto()
    MSGPACK = auto()
