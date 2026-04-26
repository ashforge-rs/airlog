"""Abstract interfaces for audit logging."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass
class AuditEvent:
    """Represents a single audit log event."""

    action: str
    actor: str
    resource: str
    resource_id: str | None = None
    outcome: str = "success"
    context: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(tz=UTC))


class AuditLogger(ABC):
    """Abstract base class for audit loggers."""

    @abstractmethod
    def log(self, event: AuditEvent) -> None:
        """Log an audit event.

        Args:
            event: The audit event to record.
        """

    def log_action(
        self,
        action: str,
        actor: str,
        resource: str,
        resource_id: str | None = None,
        outcome: str = "success",
        **context: Any,
    ) -> None:
        """Convenience method to log an action without constructing an AuditEvent manually.

        Args:
            action: The action that was performed (e.g. ``"create"``, ``"delete"``).
            actor: The identity of the entity performing the action.
            resource: The type of resource being acted upon.
            resource_id: Optional identifier for the specific resource instance.
            outcome: Whether the action succeeded or failed.  Defaults to ``"success"``.
            **context: Arbitrary additional context key-value pairs.
        """
        event = AuditEvent(
            action=action,
            actor=actor,
            resource=resource,
            resource_id=resource_id,
            outcome=outcome,
            context=context,
        )
        self.log(event)
