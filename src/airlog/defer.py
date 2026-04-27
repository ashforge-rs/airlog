"""Deferred audit event emission via context managers.

:func:`defer_context` and :func:`async_defer_context` are context managers
that hold all audit events emitted to any
:class:`~airlog.buffer.BufferedStream` within the managed scope.  When the
outermost context exits normally, the accumulated events are forwarded to
their respective streams as a single batch.  Nested contexts are transparent
– events contributed by an inner scope merge into the outermost context's
list and are flushed only when the outermost context exits.

The implementation uses a :class:`~contextvars.ContextVar` so it is
automatically propagated into :mod:`asyncio` tasks **created inside the
context**.  Tasks created *before* entering the context do not participate
in deferral.

Example::

    from airlog.buffer import BufferedStream
    from airlog.defer import defer_context

    buffered = BufferedStream(backend, flush_interval=None)

    with defer_context():
        buffered.record("step_one", principal=p, resource="job")
        buffered.record("step_two", principal=p, resource="job")
    # Both events flushed to the backend as one batch here.

Async example::

    from airlog.defer import async_defer_context

    async with async_defer_context():
        await do_async_work(buffered)
    # Events flushed when the async with block exits.

Nested contexts::

    with defer_context():
        buffered.record("outer", ...)
        with defer_context():
            buffered.record("inner", ...)
        # Inner exits – no flush yet; events accumulate in outer
    # Outer exits – all events flushed together

Error handling::

    from airlog.buffer import ErrorPolicy
    from airlog.defer import defer_context

    with defer_context(on_error=ErrorPolicy.DROP):
        raise RuntimeError("something went wrong")
    # Exception causes deferred events to be silently discarded.
"""

from __future__ import annotations

import contextlib
from collections.abc import AsyncGenerator, Generator
from contextlib import asynccontextmanager, contextmanager
from contextvars import ContextVar
from typing import TYPE_CHECKING, Any

from airlog.buffer import ErrorPolicy
from airlog.interfaces import AuditStream

if TYPE_CHECKING:
    from airlog.interfaces import AuditEvent

__all__ = [
    "async_defer_context",
    "defer_context",
]

# ---------------------------------------------------------------------------
# Internal ContextVar
# ---------------------------------------------------------------------------

#: Each entry is ``{"depth": int, "events": list[tuple[AuditStream, AuditEvent]]}``.
#: ``None`` means no deferral is active in the current context.
_DEFER_CTX: ContextVar[dict[str, Any] | None] = ContextVar("_defer_ctx", default=None)


# ---------------------------------------------------------------------------
# Internal helpers (not part of the public API)
# ---------------------------------------------------------------------------


def _try_defer(stream: AuditStream, event: AuditEvent) -> bool:
    """Capture *event* in the active defer context and return ``True``.

    Returns ``False`` immediately when no defer context is active, signalling
    the caller that the event should be emitted normally.

    Args:
        stream: The :class:`~airlog.interfaces.AuditStream` that would
            ordinarily receive *event*.
        event: The audit event to defer.

    Returns:
        ``True`` if the event was captured by the active defer context,
        ``False`` if no context is active.
    """
    state = _DEFER_CTX.get()
    if state is None:
        return False
    state["events"].append((stream, event))
    return True


def _flush_deferred(events: list[tuple[AuditStream, AuditEvent]]) -> None:
    """Emit all *events* to their originating streams.

    By the time this is called, ``_DEFER_CTX`` has already been reset to
    ``None`` so :meth:`~airlog.buffer.BufferedStream.emit` will **not**
    re-defer the events.

    Events are grouped by stream identity to preserve per-stream ordering;
    streams that raise during emission are silently skipped (best-effort).

    Args:
        events: Ordered list of ``(stream, event)`` pairs collected by the
            defer context.
    """
    # Preserve insertion order per stream
    order: list[int] = []
    by_stream: dict[int, tuple[AuditStream, list[AuditEvent]]] = {}
    for stream, event in events:
        sid = id(stream)
        if sid not in by_stream:
            by_stream[sid] = (stream, [])
            order.append(sid)
        by_stream[sid][1].append(event)

    for sid in order:
        stream_obj, stream_events = by_stream[sid]
        for event in stream_events:
            with contextlib.suppress(Exception):
                stream_obj.emit(event)


# ---------------------------------------------------------------------------
# defer_context
# ---------------------------------------------------------------------------


@contextmanager
def defer_context(
    *,
    on_error: ErrorPolicy = ErrorPolicy.DROP,
) -> Generator[None, None, None]:
    """Hold all :class:`~airlog.buffer.BufferedStream` events until the block exits.

    Events recorded to any :class:`~airlog.buffer.BufferedStream` within
    this context are captured in memory rather than forwarded to the
    backend immediately.  When the outermost ``defer_context`` exits
    normally they are flushed as one batch.

    Nesting
    -------
    Nested ``defer_context`` calls are transparent – they do not create an
    independent batch.  Events from all scopes accumulate in the outermost
    context's list and are flushed only when the outermost exits.

    Error handling
    --------------
    *on_error* controls what happens when an exception escapes the
    **outermost** context:

    * :attr:`~ErrorPolicy.DROP` *(default)* – deferred events are discarded.
    * Any other policy – deferred events are still forwarded despite the
      exception (the exception is re-raised after flushing).

    Args:
        on_error: Disposition applied to the accumulated events when an
            exception escapes the outermost context.

    Yields:
        ``None`` – this context manager yields no value.

    Example::

        with defer_context():
            stream.record("action_a", ...)
            stream.record("action_b", ...)
        # Both flushed together here.
    """
    state = _DEFER_CTX.get()

    if state is not None:
        # Nested - delegate to the existing outermost context
        state["depth"] += 1
        try:
            yield
        finally:
            state["depth"] -= 1
        return

    # Outermost context - create new state
    new_state: dict[str, Any] = {"depth": 1, "events": []}
    token = _DEFER_CTX.set(new_state)
    exc_occurred = False
    try:
        yield
    except Exception:
        exc_occurred = True
        raise
    finally:
        _DEFER_CTX.reset(token)
        if not exc_occurred or on_error is not ErrorPolicy.DROP:
            _flush_deferred(new_state["events"])


# ---------------------------------------------------------------------------
# async_defer_context
# ---------------------------------------------------------------------------


@asynccontextmanager
async def async_defer_context(
    *,
    on_error: ErrorPolicy = ErrorPolicy.DROP,
) -> AsyncGenerator[None, None]:
    """Async variant of :func:`defer_context`.

    Behaves identically to :func:`defer_context` but is designed for use
    with ``async with`` in coroutines.  The :class:`~contextvars.ContextVar`
    is propagated automatically into ``asyncio`` tasks **created inside**
    this block.

    .. note::
        Tasks spawned *before* entering this context (e.g. via
        :func:`asyncio.gather` called outside the block) do not participate
        in deferral.

    Args:
        on_error: Disposition applied to accumulated events when an exception
            escapes the outermost async context.

    Yields:
        ``None`` – this context manager yields no value.

    Example::

        async with async_defer_context():
            await do_async_work(buffered_stream)
        # Events flushed here.
    """
    state = _DEFER_CTX.get()

    if state is not None:
        # Nested
        state["depth"] += 1
        try:
            yield
        finally:
            state["depth"] -= 1
        return

    new_state: dict[str, Any] = {"depth": 1, "events": []}
    token = _DEFER_CTX.set(new_state)
    exc_occurred = False
    try:
        yield
    except Exception:
        exc_occurred = True
        raise
    finally:
        _DEFER_CTX.reset(token)
        if not exc_occurred or on_error is not ErrorPolicy.DROP:
            _flush_deferred(new_state["events"])
