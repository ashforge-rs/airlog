"""Context propagation for audit logging.

Provides a context manager :func:`audit_context` and a helper
:func:`current_context` that let callers attach a *correlation_id*,
*principal*, and arbitrary *metadata* to all :class:`~airlog.interfaces.AuditEvent`
objects emitted within a lexical scope.

The implementation uses :mod:`contextvars` so the context is automatically
propagated into :mod:`asyncio` tasks created inside the ``async with`` block
(or their sync equivalents).

Example::

    import airlog.registry as registry
    from airlog.context import audit_context, current_context

    with audit_context(correlation_id="req-abc", principal=my_principal):
        ctx = current_context()
        assert ctx["correlation_id"] == "req-abc"
        # Events recorded here automatically carry the correlation_id.

Async example::

    async with audit_context(correlation_id="req-xyz"):
        await registry.aemit(event)
"""

from __future__ import annotations

from collections.abc import AsyncGenerator, Generator
from contextlib import asynccontextmanager, contextmanager
from contextvars import ContextVar, Token
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from airlog.interfaces import Principal

__all__ = [
    "AuditContextData",
    "audit_context",
    "current_context",
]

# ---------------------------------------------------------------------------
# Internal ContextVar
# ---------------------------------------------------------------------------

#: The single ContextVar that holds the active audit context dictionary.
#: ``None`` means no context is active.
_AUDIT_CTX: ContextVar[dict[str, Any] | None] = ContextVar("_audit_ctx", default=None)


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------


class AuditContextData:
    """Snapshot of the currently active audit context.

    Instances are returned by :func:`current_context` and are read-only
    views – mutating them does not affect the live context.

    Attributes:
        correlation_id: The active correlation identifier, or ``None``.
        principal: The active :class:`~airlog.interfaces.Principal`, or ``None``.
        metadata: A copy of any extra key-value metadata attached to the context.
    """

    __slots__ = ("correlation_id", "metadata", "principal")

    def __init__(
        self,
        correlation_id: str | None,
        principal: Principal | None,
        metadata: dict[str, Any],
    ) -> None:
        self.correlation_id = correlation_id
        self.principal: Principal | None = principal
        self.metadata: dict[str, Any] = metadata

    def __repr__(self) -> str:
        return (
            f"AuditContextData(correlation_id={self.correlation_id!r}, "
            f"principal={self.principal!r}, metadata={self.metadata!r})"
        )


# ---------------------------------------------------------------------------
# current_context
# ---------------------------------------------------------------------------


def current_context() -> AuditContextData:
    """Return a snapshot of the currently active audit context.

    If called outside an :func:`audit_context` block the returned object will
    have ``None`` values for *correlation_id* and *principal*, and an empty
    *metadata* dict.

    Returns:
        An :class:`AuditContextData` with a copy of the current context.
    """
    raw = _AUDIT_CTX.get()
    if raw is None:
        return AuditContextData(correlation_id=None, principal=None, metadata={})
    return AuditContextData(
        correlation_id=raw.get("correlation_id"),
        principal=raw.get("principal"),
        metadata=dict(raw.get("metadata", {})),
    )


# ---------------------------------------------------------------------------
# _build_ctx_dict
# ---------------------------------------------------------------------------


def _build_ctx_dict(
    correlation_id: str | None,
    principal: Principal | None,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    """Merge caller-supplied values over the inherited parent context."""
    parent = _AUDIT_CTX.get() or {}
    merged_metadata = {**parent.get("metadata", {}), **metadata}
    return {
        "correlation_id": correlation_id
        if correlation_id is not None
        else parent.get("correlation_id"),
        "principal": principal if principal is not None else parent.get("principal"),
        "metadata": merged_metadata,
    }


# ---------------------------------------------------------------------------
# audit_context  (sync)
# ---------------------------------------------------------------------------


@contextmanager
def audit_context(
    correlation_id: str | None = None,
    principal: Principal | None = None,
    metadata: dict[str, Any] | None = None,
) -> Generator[AuditContextData, None, None]:
    """Synchronous context manager that sets the active audit context.

    Values from an outer :func:`audit_context` are inherited and can be
    overridden by inner ones.  Metadata dictionaries are *merged* (inner
    values win on key conflicts).

    Args:
        correlation_id: Optional correlation token to attach to all events.
        principal: Optional :class:`~airlog.interfaces.Principal` to attach.
        metadata: Optional extra key-value pairs to merge into the context.

    Yields:
        An :class:`AuditContextData` snapshot of the newly active context.

    Example::

        with audit_context(correlation_id="req-1", principal=p):
            stream.record("login", principal=p, resource="session")
    """
    ctx_dict = _build_ctx_dict(correlation_id, principal, metadata or {})
    token: Token[dict[str, Any] | None] = _AUDIT_CTX.set(ctx_dict)
    try:
        yield AuditContextData(
            correlation_id=ctx_dict.get("correlation_id"),
            principal=ctx_dict.get("principal"),
            metadata=dict(ctx_dict.get("metadata", {})),
        )
    finally:
        _AUDIT_CTX.reset(token)


# ---------------------------------------------------------------------------
# audit_context  (async)
# ---------------------------------------------------------------------------


@asynccontextmanager
async def async_audit_context(
    correlation_id: str | None = None,
    principal: Principal | None = None,
    metadata: dict[str, Any] | None = None,
) -> AsyncGenerator[AuditContextData, None]:
    """Async context manager equivalent of :func:`audit_context`.

    The context is propagated into child :mod:`asyncio` tasks automatically
    because each task inherits a *copy* of the parent's :class:`contextvars.Context`.

    Args:
        correlation_id: Optional correlation token to attach to all events.
        principal: Optional :class:`~airlog.interfaces.Principal` to attach.
        metadata: Optional extra key-value pairs to merge into the context.

    Yields:
        An :class:`AuditContextData` snapshot of the newly active context.

    Example::

        async with async_audit_context(correlation_id="req-2"):
            await stream.aemit(event)
    """
    ctx_dict = _build_ctx_dict(correlation_id, principal, metadata or {})
    token: Token[dict[str, Any] | None] = _AUDIT_CTX.set(ctx_dict)
    try:
        yield AuditContextData(
            correlation_id=ctx_dict.get("correlation_id"),
            principal=ctx_dict.get("principal"),
            metadata=dict(ctx_dict.get("metadata", {})),
        )
    finally:
        _AUDIT_CTX.reset(token)


# ---------------------------------------------------------------------------
# Context-aware record helper
# ---------------------------------------------------------------------------


def inject_context(
    *,
    correlation_id: str | None,
    principal: Principal | None,
) -> tuple[str | None, Principal | None]:
    """Return ``(correlation_id, principal)`` merged with the active context.

    Explicit caller values take priority over context values.  This helper is
    used internally by context-aware wrappers that want to honour
    :func:`audit_context` without forcing all backends to be rewritten.

    Args:
        correlation_id: Explicitly supplied correlation ID (may be ``None``).
        principal: Explicitly supplied principal (may be ``None``).

    Returns:
        A tuple of the resolved ``(correlation_id, principal)``, where context
        values fill in ``None`` caller values.
    """
    ctx = _AUDIT_CTX.get()
    if ctx is None:
        return correlation_id, principal
    resolved_cid = correlation_id if correlation_id is not None else ctx.get("correlation_id")
    resolved_principal = principal if principal is not None else ctx.get("principal")
    return resolved_cid, resolved_principal
