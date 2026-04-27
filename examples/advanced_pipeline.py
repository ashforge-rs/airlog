#!/usr/bin/env python3
"""Advanced example combining multiple airlog features.

This demonstrates a production-ready audit pipeline with:
- Context tracking
- Enrichment and redaction middleware
- Integrity verification
- Metrics collection
- Policy-based routing
"""

from datetime import timedelta

from airlog import (
    AuditPipeline,
    EnrichmentMiddleware,
    IntegrityVerificationStream,
    LoggingAdapter,
    LoguruAuditStream,
    MetricsAuditStream,
    PolicyAction,
    PolicyRouter,
    Principal,
    RedactionMiddleware,
    RetentionMiddleware,
    RetentionRule,
    add_policy,
    audit_context,
)

print("Building advanced audit pipeline...\n")

# 1. Create base streams for different destinations
security_base = LoguruAuditStream()
general_base = LoggingAdapter(logger_name="general_audit")

# 2. Wrap streams with integrity verification
security_stream = IntegrityVerificationStream(security_base)
general_stream = IntegrityVerificationStream(general_base)

# 3. Add metrics collection
security_metrics = MetricsAuditStream(security_stream)
general_metrics = MetricsAuditStream(general_stream)

# 4. Set up policy router
router = PolicyRouter(default_stream=general_metrics)

add_policy(
    router,
    name="route_security",
    condition=lambda e: e.action in ["login", "logout", "permission_change"],
    action=PolicyAction.ROUTE,
    target_stream=security_metrics,
)

# 5. Build pipeline with middleware
retention_rules = [
    RetentionRule(
        name="security",
        condition=lambda e: e.action in ["login", "logout"],
        retention_period=timedelta(days=365),
    ),
    RetentionRule(
        name="default",
        condition=lambda e: True,
        retention_period=timedelta(days=90),
    ),
]

pipeline = (
    AuditPipeline(router)
    .add(
        EnrichmentMiddleware(
            {
                "environment": "production",
                "application": "web-api",
                "version": "2.1.0",
            }
        )
    )
    .add(RedactionMiddleware(fields_to_redact=["password", "api_key", "token"]))
    .add(RetentionMiddleware(rules=retention_rules))
)

print("✓ Pipeline configured with:")
print("  - Integrity verification")
print("  - Metrics collection")
print("  - Policy-based routing")
print("  - Enrichment middleware")
print("  - Redaction middleware")
print("  - Retention management")

# 6. Use the pipeline with context
print("\nRecording events...\n")

with audit_context(
    principal=Principal(subject="alice", auth_method="password"),
    correlation_id="req-12345",
):
    # Security event - routed to security stream
    pipeline.record(
        "login",
        resource="session",
        resource_id="ses-42",
        metadata={"ip": "192.168.1.100", "password": "secret"},  # Will be redacted
    )
    print("✓ Login event (routed to security stream)")

    # General event - routed to general stream
    pipeline.record(
        "data_query",
        resource="database",
        resource_id="customers",
        metadata={"rows": 150},
    )
    print("✓ Data query event (routed to general stream)")

# 7. Check metrics
print("\nSecurity stream metrics:")
security_metrics_data = security_metrics.get_metrics()
print(f"  Total events: {security_metrics_data['total_events']}")

print("\nGeneral stream metrics:")
general_metrics_data = general_metrics.get_metrics()
print(f"  Total events: {general_metrics_data['total_events']}")

print("\n✓ Production-ready audit pipeline operational!")
