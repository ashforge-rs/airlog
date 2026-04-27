#!/usr/bin/env python3
"""Example demonstrating integrity verification.

IntegrityVerificationStream wraps another stream and provides
tamper detection through cryptographic checksums.
"""

from airlog import IntegrityVerificationStream, LoguruAuditStream, Principal

# Create base stream and wrap with integrity verification
base_stream = LoguruAuditStream()
integrity_stream = IntegrityVerificationStream(base_stream)

print("Recording events with integrity verification...\n")

# Record an event
event = integrity_stream.record(
    "sensitive_operation",
    principal=Principal(subject="alice", auth_method="api_key"),
    resource="database",
    resource_id="prod-db",
    metadata={"operation": "DELETE", "table": "users"},
)

print(f"✓ Event recorded: {event.event_id}")
print(f"  Checksum: {event.checksum[:16]}...")

# Verify integrity
if event.verify():
    print("✓ Event integrity verified - no tampering detected")
else:
    print("✗ Event integrity check failed!")

# Demonstrate tamper detection
print("\nSimulating tampering...")
# Create a modified version of the event (in real scenarios, this would come from storage)
tampered_event = event.__class__(
    **{
        **event.__dict__,
        "action": "harmless_read",  # Attacker tries to change the action
    }
)

if tampered_event.verify():
    print("✗ Tampered event verified (this should not happen!)")
else:
    print("✓ Tampering detected - checksum mismatch!")

# Record more events
integrity_stream.record(
    "config_change",
    principal=Principal(subject="admin", auth_method="session"),
    resource="configuration",
    resource_id="app-config",
    metadata={"key": "max_retries", "old_value": "3", "new_value": "5"},
)

print("\n✓ Integrity verification protects against tampering")
