#!/usr/bin/env python3
"""Example demonstrating OCSF (Open Cybersecurity Schema Framework) format.

This example requires the ocsf optional dependency:
    uv add "airlog[ocsf]"
"""

try:
    from airlog import OcsfClass, OcsfSeverity, OcsfStream, Principal

    print("Recording events in OCSF format...\n")

    # Create OCSF stream
    stream = OcsfStream()

    # Record authentication event
    event = stream.record(
        "login",
        principal=Principal(
            subject="alice",
            auth_method="password",
            metadata={"ip": "192.168.1.100"},
        ),
        resource="session",
        resource_id="ses-42",
        ocsf_class=OcsfClass.AUTHENTICATION,
        ocsf_severity=OcsfSeverity.INFORMATIONAL,
    )

    print(f"✓ Authentication event recorded")
    print(f"  OCSF Class: {OcsfClass.AUTHENTICATION}")
    print(f"  OCSF Severity: {OcsfSeverity.INFORMATIONAL}")

    # Record security finding
    stream.record(
        "suspicious_activity",
        principal=Principal(subject="eve", auth_method="unknown"),
        resource="api",
        resource_id="/api/admin",
        ocsf_class=OcsfClass.SECURITY_FINDING,
        ocsf_severity=OcsfSeverity.HIGH,
        metadata={
            "reason": "Multiple failed authentication attempts",
            "attempt_count": 5,
        },
    )

    print(f"✓ Security finding recorded")
    print(f"  OCSF Class: {OcsfClass.SECURITY_FINDING}")
    print(f"  OCSF Severity: {OcsfSeverity.HIGH}")

    # Record data access
    stream.record(
        "data_access",
        principal=Principal(subject="alice", auth_method="session"),
        resource="database",
        resource_id="customer_records",
        ocsf_class=OcsfClass.DATA_ACCESS,
        ocsf_severity=OcsfSeverity.INFORMATIONAL,
    )

    print(f"✓ Data access event recorded")

    print("\n✓ OCSF format provides standardized security event schema")

except ImportError:
    print("❌ OCSF support not available")
    print("   Install with: uv add 'airlog[ocsf]'")
    print("   Or: pip install 'airlog[ocsf]'")
