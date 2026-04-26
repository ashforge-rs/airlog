# airlog

A Python audit logging library with pluggable backends.  The first (and currently only) supported backend is [loguru](https://github.com/Delgan/loguru) with JSON-formatted output.

## Features

- Simple `AuditLogger` abstract interface to swap logging backends without changing application code
- Structured `AuditEvent` dataclass capturing action, actor, resource, outcome, and arbitrary context
- `LoguruAuditLogger` – a ready-to-use implementation that serialises every audit event as a newline-delimited JSON record via loguru

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
from airlog import LoguruAuditLogger

audit = LoguruAuditLogger()

# Convenience helper – kwargs become context fields
audit.log_action("login", actor="alice", resource="session", ip="10.0.0.1")

# Full control via AuditEvent
from airlog import AuditEvent
event = AuditEvent(
    action="delete",
    actor="bob",
    resource="document",
    resource_id="doc-42",
    outcome="success",
    context={"reason": "expired"},
)
audit.log(event)
```

## Development

```bash
# install deps (including dev extras)
uv sync

# lint
uv run ruff check src/ tests/

# format
uv run ruff format src/ tests/

# tests
uv run pytest
```