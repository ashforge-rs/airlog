"""Module-level audit stream registry.

Provides a simple, thread-safe registry that maps string names to
:class:`~airlog.interfaces.AuditStream` instances.  The top-level
:func:`emit` and :func:`aemit` functions fan events out to registered
backends, with optional string-list or predicate-based routing.

Example – register and emit::

    import airlog.registry as registry
    from airlog import Principal
    from airlog.adapters import LoggingAdapter

    registry.register("logging", LoggingAdapter())
    registry.register("db", my_db_stream)

    event = my_stream.record("login", principal=p, resource="session")
    registry.emit(event)                            # all backends
    registry.emit(event, backends=["logging"])      # named subset
    registry.emit(event, backends=lambda n, _: n.startswith("db"))  # predicate

Async usage::

    results = await registry.aemit(event)
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable
from typing import Any

from airlog.interfaces import AuditEvent, AuditStream

__all__ = [
    "aemit",
    "deregister",
    "emit",
    "list_backends",
    "register",
]

_registry: dict[str, AuditStream] = {}
_registry_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Registration helpers
# ---------------------------------------------------------------------------


def register(name: str, stream: AuditStream) -> None:
    """Register *stream* under *name*.

    Replaces any previously registered stream with the same name.

    Args:
        name: Unique string identifier for this backend.
        stream: An :class:`~airlog.interfaces.AuditStream` instance.
    """
    with _registry_lock:
        _registry[name] = stream


def deregister(name: str) -> None:
    """Remove the backend registered as *name*.

    Args:
        name: The name passed to :func:`register`.

    Raises:
        KeyError: If *name* is not currently registered.
    """
    with _registry_lock:
        del _registry[name]


def list_backends() -> dict[str, AuditStream]:
    """Return a snapshot of the current registry.

    Returns:
        A shallow copy of the ``{name: stream}`` mapping.  Mutations to the
        returned dict do not affect the registry.
    """
    with _registry_lock:
        return dict(_registry)


# ---------------------------------------------------------------------------
# Internal routing helper
# ---------------------------------------------------------------------------

BackendFilter = list[str] | Callable[[str, AuditStream], bool] | None


def _select_backends(
    backends: BackendFilter,
    registry_snapshot: dict[str, AuditStream],
) -> list[tuple[str, AuditStream]]:
    """Return ``(name, stream)`` pairs that match *backends*."""
    match backends:
        case None:
            return list(registry_snapshot.items())
        case list():
            return [(n, s) for n, s in registry_snapshot.items() if n in backends]
        case _ if callable(backends):
            return [(n, s) for n, s in registry_snapshot.items() if backends(n, s)]
        case _:
            return []


# ---------------------------------------------------------------------------
# Synchronous emit
# ---------------------------------------------------------------------------


def emit(
    event: AuditEvent,
    backends: BackendFilter = None,
) -> dict[str, bool]:
    """Emit *event* to registered backends and return per-backend results.

    Args:
        event: The :class:`~airlog.interfaces.AuditEvent` to emit.
        backends: Controls which backends receive the event:

            * ``None`` *(default)* – all registered backends.
            * :class:`list` of names – only the named backends.
            * Callable ``(name, stream) -> bool`` – backends for which the
              predicate returns ``True``.

    Returns:
        A ``{name: success}`` dict.  ``success`` is ``True`` when
        :meth:`~airlog.interfaces.AuditStream.emit` returned without raising,
        ``False`` otherwise.
    """
    snapshot = list_backends()
    selected = _select_backends(backends, snapshot)
    results: dict[str, bool] = {}
    for name, stream in selected:
        try:
            stream.emit(event)
            results[name] = True
        except Exception:
            results[name] = False
    return results


# ---------------------------------------------------------------------------
# Async emit
# ---------------------------------------------------------------------------


async def aemit(
    event: AuditEvent,
    backends: BackendFilter = None,
) -> dict[str, bool]:
    """Asynchronously emit *event* to registered backends.

    Awaits :meth:`~airlog.interfaces.AuditStream.aemit` for each selected
    backend (sequentially; use :func:`asyncio.gather` externally for
    concurrent fan-out if needed).

    Args:
        event: The :class:`~airlog.interfaces.AuditEvent` to emit.
        backends: Same semantics as in :func:`emit`.

    Returns:
        A ``{name: success}`` dict where ``success`` is the boolean returned
        by :meth:`~airlog.interfaces.AuditStream.aemit`.
    """
    snapshot = list_backends()
    selected = _select_backends(backends, snapshot)
    results: dict[str, bool] = {}
    for name, stream in selected:
        try:
            results[name] = await stream.aemit(event)
        except Exception:
            results[name] = False
    return results


def emit_sync_or_async(
    event: AuditEvent,
    backends: BackendFilter = None,
) -> Any:
    """Emit *event* using the async path if a loop is running, else sync.

    This helper lets framework-agnostic code call emit without knowing whether
    it is executing inside an async context.

    Args:
        event: The :class:`~airlog.interfaces.AuditEvent` to emit.
        backends: Same semantics as in :func:`emit`.

    Returns:
        When called from a running event loop: a coroutine that must be
        awaited.  When called from synchronous code: the ``{name: bool}``
        results dict directly.
    """
    try:
        asyncio.get_running_loop()
        return aemit(event, backends)
    except RuntimeError:
        return emit(event, backends)
