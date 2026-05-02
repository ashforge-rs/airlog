#!/usr/bin/env python3
"""Example demonstrating replayable streams for testing.

ReplayableStream captures events and allows them to be replayed,
which is useful for testing and debugging.
"""

from airlog import Principal, ReplayableStream

# Create a replayable stream
stream = ReplayableStream()

print("Recording events to replayable stream...\n")

# Record events
stream.record(
    "login",
    principal=Principal(subject="alice", auth_method="password"),
    resource="session",
    resource_id="ses-1",
)

stream.record(
    "file_access",
    principal=Principal(subject="alice", auth_method="session"),
    resource="document",
    resource_id="doc-42",
)

stream.record(
    "logout",
    principal=Principal(subject="alice", auth_method="session"),
    resource="session",
    resource_id="ses-1",
)

# Get recorded events
events = stream.get_recorded_events()
print(f"✓ Recorded {len(events)} events")

# Display events
for i, event in enumerate(events, 1):
    print(f"{i}. {event.action} - {event.resource} - {event.principal.subject}")

# Clear the stream
stream.clear()
print("\n✓ Stream cleared")

# Verify it's empty
events = stream.get_recorded_events()
print(f"  Events after clear: {len(events)}")

print("\n✓ ReplayableStream useful for testing and debugging")
