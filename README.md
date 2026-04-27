# airlog

A Python audit logging library with pluggable backends and compliance-grade features.

## Features

| Feature | Details |
|---|---|
| **Immutable log stream** | `AuditStream` is append-only – no modify or delete operations |
| **Structured events** | `AuditEvent` is a frozen dataclass with nanosecond-precision timestamps |
| **Correlation IDs** | `correlation_id` field tracks a request across its entire lifecycle |
| **Principal tracking** | `Principal` captures subject, auth method (password / API key / certificate / JWT / …), and arbitrary metadata |
| **Integrity verification** | SHA-256 checksum over all event fields; `event.verify()` detects tampering |
| **Unique event IDs** | UUID v4 per event + monotonically increasing sequence numbers |
| **Pluggable backends** | Implement `AuditStream.emit()` to target stdout, files, syslog, databases, or any custom destination |
| **loguru / JSON** | `LoguruAuditStream` ships out of the box for newline-delimited JSON output |
| **Thread-safe** | Sequence counter is protected by a lock |

## Requirements

- Python ≥ 3.11
- [uv](https://github.com/astral-sh/uv) (recommended package manager)

## Installation

```bash
uv add airlog
```

Or with pip:

```bash
pip install airlog
```

## Quick start

```python
from airlog import LoguruAuditStream, Principal

stream = LoguruAuditStream()          # JSON → stderr by default

event = stream.record(
    "login",
    principal=Principal(subject="alice", auth_method="password", metadata={"ip": "10.0.0.1"}),
    resource="session",
    resource_id="ses-42",
    correlation_id="req-abc123",
)

# Verify integrity at any time
assert event.verify()
print(event.event_id)     # UUID v4
print(event.sequence)     # 1
print(event.timestamp)    # UTC datetime
print(event.checksum)     # SHA-256 hex
```

### Custom backend

```python
from airlog import AuditEvent, AuditStream, Principal

class SyslogStream(AuditStream):
    def emit(self, event: AuditEvent) -> None:
        import syslog
        syslog.syslog(f"[{event.sequence}] {event.action} by {event.principal.subject}")

stream = SyslogStream()
stream.record(
    "delete",
    principal=Principal(subject="bob", auth_method="certificate"),
    resource="document",
    resource_id="doc-7",
    outcome="success",
)
```

### Sample JSON output (`LoguruAuditStream`)

Each call to `record()` emits one newline-delimited JSON line.  All audit
fields are stored under `record.extra`:

```json
{
  "record": {
    "extra": {
      "event_id": "4e1b2f3c-…",
      "sequence": 1,
      "timestamp_ns": 1735000000000000000,
      "timestamp": "2025-01-01T00:00:00+00:00",
      "action": "login",
      "principal_subject": "alice",
      "principal_auth_method": "password",
      "principal_metadata": {"ip": "10.0.0.1"},
      "resource": "session",
      "resource_id": "ses-42",
      "outcome": "success",
      "correlation_id": "req-abc123",
      "context": {},
      "checksum": "a3f1…"
    }
  }
}
```

## Examples

Comprehensive examples are available in the [`examples/`](examples/) directory:

- **Basic Usage**: Simple getting started examples with various adapters
- **Pipeline & Middleware**: Building pipelines with enrichment and redaction
- **Context Tracking**: Automatic event enrichment using audit contexts
- **Metrics & Monitoring**: Collecting metrics from audit events
- **Policy & Routing**: Policy-based event routing to different streams
- **Integrity & Verification**: Tamper detection and integrity checking
- **Retention Management**: Configuring retention rules and automatic cleanup
- **Backend Adapters**: OCSF format and OpenTelemetry integration
- **Registry**: Using the global pipeline registry

Run any example:

```bash
python examples/basic_usage.py
# or
uv run examples/basic_usage.py
```

See [`examples/README.md`](examples/README.md) for the complete list and details.

## Development

```bash
uv sync                              # install all deps

uv run ruff check src/ tests/        # lint
uv run ruff format src/ tests/       # format

uv run pytest                        # tests
uv run pytest --cov=airlog           # with coverage (currently 100 %)
```