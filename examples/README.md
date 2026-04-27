# Airlog Examples

This directory contains examples demonstrating various features of the airlog library.

## Getting Started

Before running these examples, install airlog with optional dependencies:

```bash
uv add airlog
# Or with all optional dependencies:
uv add "airlog[ocsf]"
```

## Examples

### Basic Usage

- **[basic_usage.py](basic_usage.py)** - Simple getting started example with LoguruAuditStream
- **[logging_adapter.py](logging_adapter.py)** - Using the standard library logging adapter

### Pipeline & Middleware

- **[pipeline_middleware.py](pipeline_middleware.py)** - Building audit pipelines with enrichment and redaction middleware
- **[advanced_pipeline.py](advanced_pipeline.py)** - Complex multi-feature pipeline combining several capabilities

### Context Tracking

- **[context_tracking.py](context_tracking.py)** - Using audit context to automatically enrich events
- **[async_context.py](async_context.py)** - Async context tracking with asyncio

### Metrics & Monitoring

- **[metrics_monitoring.py](metrics_monitoring.py)** - Collecting metrics from audit events

### Policy & Routing

- **[policy_routing.py](policy_routing.py)** - Policy-based event routing to different streams

### Integrity & Verification

- **[integrity_verification.py](integrity_verification.py)** - Integrity checking and tamper detection
- **[replayable_stream.py](replayable_stream.py)** - Using replayable streams for testing

### Retention Management

- **[retention_management.py](retention_management.py)** - Configuring retention rules and automatic cleanup

### Backend Adapters

- **[ocsf_format.py](ocsf_format.py)** - Using OCSF (Open Cybersecurity Schema Framework) format
- **[opentelemetry_integration.py](opentelemetry_integration.py)** - Integrating with OpenTelemetry

### Registry

- **[registry_usage.py](registry_usage.py)** - Using the global pipeline registry

## Running Examples

Each example is standalone and can be run directly:

```bash
python examples/basic_usage.py
```

Or with uv:

```bash
uv run examples/basic_usage.py
```

## Note on Dependencies

Some examples require optional dependencies:
- `ocsf_format.py` requires `ocsf-lib` (install with `uv add "airlog[ocsf]"`)
- `opentelemetry_integration.py` requires `opentelemetry-api`
