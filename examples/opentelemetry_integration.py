#!/usr/bin/env python3
"""Example demonstrating OpenTelemetry integration.

This example requires opentelemetry-api:
    uv add opentelemetry-api
"""

try:
    from airlog import OpenTelemetryAdapter, Principal

    print("Recording events to OpenTelemetry...\n")

    # Create OpenTelemetry adapter
    stream = OpenTelemetryAdapter()

    # Record events - these will be sent as OpenTelemetry logs
    stream.record(
        "api_request",
        principal=Principal(subject="alice", auth_method="api_key"),
        resource="api",
        resource_id="/api/v1/users",
        metadata={
            "method": "GET",
            "status_code": 200,
            "duration_ms": 45,
        },
    )

    print("✓ API request event sent to OpenTelemetry")

    stream.record(
        "database_query",
        principal=Principal(subject="api-service", auth_method="service_account"),
        resource="database",
        resource_id="users_table",
        metadata={
            "query": "SELECT * FROM users WHERE active = true",
            "rows_returned": 150,
            "duration_ms": 12,
        },
    )

    print("✓ Database query event sent to OpenTelemetry")

    stream.record(
        "cache_miss",
        principal=Principal(subject="api-service", auth_method="service_account"),
        resource="cache",
        resource_id="user:alice",
        metadata={"cache_type": "redis"},
    )

    print("✓ Cache event sent to OpenTelemetry")

    print("\n✓ Events integrated with OpenTelemetry observability stack")
    print("  Configure OpenTelemetry SDK to export to your backend")

except ImportError:
    print("❌ OpenTelemetry support not available")
    print("   Install with: uv add opentelemetry-api")
    print("   Or: pip install opentelemetry-api")
