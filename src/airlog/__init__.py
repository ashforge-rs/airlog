"""airlog – compliance-grade audit logging library.

One interface, swappable backends.

Quick-start::

    from airlog import AuditPipeline, LoggingAdapter, Principal
    from airlog.middleware import EnrichmentMiddleware, RedactionMiddleware
    import airlog.registry as registry

    stream = LoggingAdapter()
    pipeline = AuditPipeline(stream).add(RedactionMiddleware())
    registry.register("default", pipeline)

    event = pipeline.record(
        "login",
        principal=Principal(subject="alice", auth_method="password"),
        resource="session",
        correlation_id="req-abc123",
    )
    assert event.verify()

Phase 2 – ecosystem features::

    from airlog.context import audit_context, current_context
    from airlog.metrics import MetricsAuditStream
    from airlog.policy import PolicyRouter, PolicyAction, DeliveryError
    from airlog.integrity import IntegrityVerificationStream, IntegrityViolation
    from airlog.retention import RetentionMiddleware, RetentionRule
"""

from __future__ import annotations

from airlog.adapters.logging_adapter import LoggingAdapter
from airlog.adapters.ocsf_adapter import OcsfStream
from airlog.adapters.opentelemetry_adapter import OpenTelemetryAdapter
from airlog.context import AuditContextData, async_audit_context, audit_context, current_context
from airlog.integrity import IntegrityVerificationStream, IntegrityViolation, ReplayableStream
from airlog.interfaces import AuditEvent, AuditStream, HealthStatus, Principal, StreamFeature
from airlog.loguru_handler import LoguruAuditStream
from airlog.metrics import MetricsAuditStream
from airlog.middleware import (
    AuditMiddleware,
    AuditPipeline,
    EnrichmentMiddleware,
    RedactionMiddleware,
)
from airlog.ocsf_support import OcsfClass, OcsfSeverity
from airlog.policy import DeliveryError, Policy, PolicyAction, PolicyRouter, add_policy
from airlog.retention import (
    RetentionCapableStream,
    RetentionMiddleware,
    RetentionResult,
    RetentionRule,
)
from airlog.serialization import SerializationFormat

__all__ = [
    "AuditContextData",
    "AuditEvent",
    "AuditMiddleware",
    "AuditPipeline",
    "AuditStream",
    "DeliveryError",
    "EnrichmentMiddleware",
    "HealthStatus",
    "IntegrityVerificationStream",
    "IntegrityViolation",
    "LoggingAdapter",
    "LoguruAuditStream",
    "MetricsAuditStream",
    "OcsfClass",
    "OcsfSeverity",
    "OcsfStream",
    "OpenTelemetryAdapter",
    "Policy",
    "PolicyAction",
    "PolicyRouter",
    "Principal",
    "RedactionMiddleware",
    "ReplayableStream",
    "RetentionCapableStream",
    "RetentionMiddleware",
    "RetentionResult",
    "RetentionRule",
    "SerializationFormat",
    "StreamFeature",
    "add_policy",
    "async_audit_context",
    "audit_context",
    "current_context",
]
