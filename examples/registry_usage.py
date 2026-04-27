#!/usr/bin/env python3
"""Example demonstrating the global pipeline registry.

The registry allows you to register named pipelines and retrieve them
throughout your application.
"""

import airlog.registry as registry
from airlog import (
    AuditPipeline,
    EnrichmentMiddleware,
    LoggingAdapter,
    LoguruAuditStream,
    Principal,
    RedactionMiddleware,
)

print("Setting up global pipeline registry...\n")

# Create and register a default pipeline
default_stream = LoguruAuditStream()
default_pipeline = (
    AuditPipeline(default_stream)
    .add(EnrichmentMiddleware({"environment": "production"}))
    .add(RedactionMiddleware())
)
registry.register("default", default_pipeline)
print("✓ Registered 'default' pipeline")

# Create and register a security-focused pipeline
security_stream = LoggingAdapter(logger_name="security_audit")
security_pipeline = AuditPipeline(security_stream).add(
    EnrichmentMiddleware({"security": True, "requires_review": True})
)
registry.register("security", security_pipeline)
print("✓ Registered 'security' pipeline")

# Retrieve and use pipelines from anywhere in the application
print("\nUsing pipelines from registry...\n")


def some_business_logic() -> None:
    """Simulate business logic that needs audit logging."""
    pipeline = registry.get("default")

    pipeline.record(
        "business_action",
        principal=Principal(subject="alice", auth_method="session"),
        resource="order",
        resource_id="order-123",
    )
    print("✓ Recorded to 'default' pipeline")


def security_sensitive_operation() -> None:
    """Simulate security-sensitive operation."""
    pipeline = registry.get("security")

    pipeline.record(
        "security_action",
        principal=Principal(subject="admin", auth_method="api_key"),
        resource="encryption_key",
        resource_id="key-789",
        metadata={"operation": "rotate"},
    )
    print("✓ Recorded to 'security' pipeline")


# Call functions that use the registry
some_business_logic()
security_sensitive_operation()

# List all registered pipelines
print(f"\nRegistered pipelines: {list(registry.list_pipelines())}")

# Clean up
registry.unregister("security")
print("\n✓ Unregistered 'security' pipeline")
print(f"Remaining pipelines: {list(registry.list_pipelines())}")
