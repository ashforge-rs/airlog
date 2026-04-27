#!/usr/bin/env python3
"""Example demonstrating policy-based event routing.

PolicyRouter allows you to route events to different streams based on
configurable policies.
"""

from airlog import (
    LoggingAdapter,
    LoguruAuditStream,
    PolicyAction,
    PolicyRouter,
    Principal,
    add_policy,
)

# Create multiple destination streams
security_stream = LoguruAuditStream()
general_stream = LoguruAuditStream()
admin_stream = LoggingAdapter(logger_name="admin_audit")

# Create policy router with default stream
router = PolicyRouter(default_stream=general_stream)

# Add policies using the global add_policy function
# Route security events to security stream
add_policy(
    router,
    name="security_events",
    condition=lambda event: event.action in ["login", "logout", "permission_change"],
    action=PolicyAction.ROUTE,
    target_stream=security_stream,
)

# Route admin actions to both admin stream and general stream
add_policy(
    router,
    name="admin_actions",
    condition=lambda event: event.principal.subject == "admin",
    action=PolicyAction.ROUTE,
    target_stream=admin_stream,
)

# Drop test events
add_policy(
    router,
    name="drop_test_events",
    condition=lambda event: event.metadata.get("test", False),
    action=PolicyAction.DROP,
)

print("Recording events with policy-based routing...\n")

# Security event - routed to security_stream
router.record(
    "login",
    principal=Principal(subject="alice", auth_method="password"),
    resource="session",
)
print("✓ Login event routed to security stream")

# Admin event - routed to admin_stream
router.record(
    "user_created",
    principal=Principal(subject="admin", auth_method="api_key"),
    resource="user",
    resource_id="user-123",
)
print("✓ Admin event routed to admin stream")

# General event - goes to default stream
router.record(
    "data_export",
    principal=Principal(subject="alice", auth_method="session"),
    resource="report",
    resource_id="report-456",
)
print("✓ General event routed to default stream")

# Test event - dropped
router.record(
    "test_action",
    principal=Principal(subject="tester", auth_method="session"),
    resource="test",
    metadata={"test": True},
)
print("✓ Test event dropped by policy")

print("\n✓ All events routed according to policies")
