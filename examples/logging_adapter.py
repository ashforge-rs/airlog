#!/usr/bin/env python3
"""Example using the standard library logging adapter.

This example shows how to use LoggingAdapter to send audit events
to Python's standard logging system.
"""

import logging

from airlog import LoggingAdapter, Principal

# Configure standard logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)

# Create an audit stream backed by standard logging
stream = LoggingAdapter(logger_name="audit")

print("Recording audit events to standard logging...\n")

# Record events
stream.record(
    "user_created",
    principal=Principal(subject="admin", auth_method="api_key"),
    resource="user",
    resource_id="user-123",
    metadata={"username": "bob", "email": "bob@example.com"},
)

stream.record(
    "permission_granted",
    principal=Principal(subject="admin", auth_method="api_key"),
    resource="user",
    resource_id="user-123",
    metadata={"permission": "read:documents"},
)

stream.record(
    "api_call",
    principal=Principal(subject="bob", auth_method="api_key"),
    resource="api",
    resource_id="/api/v1/documents",
    metadata={"method": "GET", "status_code": 200},
)

print("\n✓ Events sent to logging system")
