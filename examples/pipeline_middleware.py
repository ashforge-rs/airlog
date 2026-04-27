#!/usr/bin/env python3
"""Example demonstrating audit pipelines with middleware.

This shows how to build a pipeline with:
- Enrichment middleware (adds extra fields)
- Redaction middleware (removes sensitive data)
"""

from airlog import (
    AuditPipeline,
    EnrichmentMiddleware,
    LoguruAuditStream,
    Principal,
    RedactionMiddleware,
)

# Create the base stream
base_stream = LoguruAuditStream()

# Build a pipeline with middleware
pipeline = (
    AuditPipeline(base_stream)
    .add(
        EnrichmentMiddleware(
            {
                "environment": "production",
                "service": "auth-api",
                "version": "1.2.3",
            }
        )
    )
    .add(RedactionMiddleware(fields_to_redact=["password", "credit_card", "ssn"]))
)

print("Recording events through pipeline with enrichment and redaction...\n")

# Record an event - enrichment will add fields, redaction will remove sensitive ones
event = pipeline.record(
    "login_attempt",
    principal=Principal(subject="alice", auth_method="password"),
    resource="session",
    metadata={
        "ip": "192.168.1.100",
        "password": "secret123",  # This will be redacted
        "credit_card": "4111-1111-1111-1111",  # This will be redacted
        "user_agent": "Mozilla/5.0",
    },
)

print(f"✓ Event recorded: {event.event_id}")
print(f"  Metadata keys: {list(event.metadata.keys())}")
print(f"  Note: 'password' and 'credit_card' should be redacted")

# Record another event
pipeline.record(
    "data_export",
    principal=Principal(subject="alice", auth_method="session"),
    resource="user_data",
    resource_id="user-456",
    metadata={
        "export_format": "json",
        "record_count": 1500,
        "ssn": "123-45-6789",  # This will be redacted
    },
)

print("\n✓ Pipeline processed all events")
