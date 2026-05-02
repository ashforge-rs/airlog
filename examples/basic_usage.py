#!/usr/bin/env python3
"""Basic usage example for airlog.

This example demonstrates the simplest way to get started with airlog
using the LoguruAuditStream backend.
"""

from airlog import LoguruAuditStream, Principal

# Create an audit stream that outputs JSON to stderr
stream = LoguruAuditStream()

# Record a simple login event
event = stream.record(
    "login",
    principal=Principal(
        subject="alice",
        auth_method="password",
        metadata={"ip": "10.0.0.1", "user_agent": "Mozilla/5.0"},
    ),
    resource="session",
    resource_id="ses-42",
    correlation_id="req-abc123",
)

print(f"\n✓ Event recorded: {event.event_id}")
print(f"  Action: {event.action}")
print(f"  Principal: {event.principal.subject}")
print(f"  Timestamp: {event.timestamp}")
print(f"  Sequence: {event.sequence}")

# Verify the event integrity
if event.verify():
    print("✓ Event integrity verified")
else:
    print("✗ Event integrity check failed!")

# Record more events
stream.record(
    "file_access",
    principal=Principal(subject="alice", auth_method="session"),
    resource="document",
    resource_id="doc-789",
    correlation_id="req-abc123",
    outcome="success",
)

stream.record(
    "logout",
    principal=Principal(subject="alice", auth_method="session"),
    resource="session",
    resource_id="ses-42",
    correlation_id="req-abc123",
)

print("\n✓ All events recorded successfully")
