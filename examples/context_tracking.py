#!/usr/bin/env python3
"""Example demonstrating audit context for automatic event enrichment.

Audit context allows you to set contextual information that automatically
enriches all events recorded within that context.
"""

from airlog import LoguruAuditStream, Principal, audit_context, current_context

stream = LoguruAuditStream()

print("Recording events with audit context...\n")


def process_user_request(user_id: str, request_id: str) -> None:
    """Simulate processing a user request within an audit context."""
    # Set up audit context for this request
    with audit_context(
        principal=Principal(subject=user_id, auth_method="session"),
        correlation_id=request_id,
        environment="production",
        service="api",
    ):
        # Get current context to verify
        ctx = current_context()
        print(f"Current context: correlation_id={ctx.correlation_id}")

        # All events recorded here will automatically include context
        stream.record(
            "request_started",
            resource="api",
            resource_id="/api/v1/users",
        )

        stream.record(
            "database_query",
            resource="database",
            resource_id="users_table",
            metadata={"query": "SELECT * FROM users WHERE id = ?"},
        )

        stream.record(
            "request_completed",
            resource="api",
            resource_id="/api/v1/users",
            outcome="success",
            metadata={"duration_ms": 45},
        )


# Process multiple requests
process_user_request("alice", "req-001")
print()
process_user_request("bob", "req-002")

print("\n✓ All events enriched with context automatically")
