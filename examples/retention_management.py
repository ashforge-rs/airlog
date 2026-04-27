#!/usr/bin/env python3
"""Example demonstrating retention management.

RetentionMiddleware automatically handles event lifecycle according
to configurable retention rules.
"""

from datetime import timedelta

from airlog import (
    AuditPipeline,
    LoguruAuditStream,
    Principal,
    RetentionMiddleware,
    RetentionRule,
)

# Define retention rules
rules = [
    RetentionRule(
        name="security_events",
        condition=lambda event: event.action in ["login", "logout", "permission_change"],
        retention_period=timedelta(days=365),  # Keep for 1 year
    ),
    RetentionRule(
        name="general_events",
        condition=lambda event: True,  # Catch-all
        retention_period=timedelta(days=90),  # Keep for 90 days
    ),
]

# Create pipeline with retention middleware
base_stream = LoguruAuditStream()
pipeline = AuditPipeline(base_stream).add(RetentionMiddleware(rules=rules))

print("Recording events with retention policies...\n")

# Record various events
event1 = pipeline.record(
    "login",
    principal=Principal(subject="alice", auth_method="password"),
    resource="session",
)
print(f"✓ Login event (security) - retention: 365 days")

event2 = pipeline.record(
    "data_export",
    principal=Principal(subject="alice", auth_method="session"),
    resource="report",
    resource_id="report-123",
)
print(f"✓ Data export (general) - retention: 90 days")

event3 = pipeline.record(
    "permission_change",
    principal=Principal(subject="admin", auth_method="api_key"),
    resource="user",
    resource_id="user-456",
    metadata={"permission": "admin", "action": "granted"},
)
print(f"✓ Permission change (security) - retention: 365 days")

# In production, you would typically have a background job that:
# 1. Queries events older than their retention period
# 2. Archives or deletes them according to policy
# 3. Runs on a schedule (e.g., daily)

print("\n✓ Events recorded with retention metadata")
print("  In production, a background job would enforce retention policies")
