#!/usr/bin/env python3
"""Example demonstrating metrics collection from audit events.

MetricsAuditStream wraps another stream and collects metrics about
events passing through it.
"""

from airlog import LoguruAuditStream, MetricsAuditStream, Principal

# Create base stream and wrap it with metrics collection
base_stream = LoguruAuditStream()
metrics_stream = MetricsAuditStream(base_stream)

print("Recording events and collecting metrics...\n")

# Record various events
for i in range(5):
    metrics_stream.record(
        "login",
        principal=Principal(subject=f"user{i}", auth_method="password"),
        resource="session",
        outcome="success",
    )

for i in range(3):
    metrics_stream.record(
        "login",
        principal=Principal(subject=f"user{i}", auth_method="password"),
        resource="session",
        outcome="failure",
        metadata={"reason": "invalid_password"},
    )

metrics_stream.record(
    "data_access",
    principal=Principal(subject="alice", auth_method="session"),
    resource="database",
    outcome="success",
)

# Get metrics
metrics = metrics_stream.get_metrics()

print("=== Metrics Summary ===")
print(f"Total events: {metrics['total_events']}")
print(f"\nEvents by action:")
for action, count in metrics["by_action"].items():
    print(f"  {action}: {count}")

print(f"\nEvents by outcome:")
for outcome, count in metrics["by_outcome"].items():
    print(f"  {outcome}: {count}")

print(f"\nEvents by principal:")
for principal, count in metrics["by_principal"].items():
    print(f"  {principal}: {count}")

# Reset metrics
metrics_stream.reset_metrics()
print("\n✓ Metrics reset")
