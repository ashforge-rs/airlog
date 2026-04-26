"""Built-in adapter implementations for common logging backends.

Adapters bridge :class:`~airlog.interfaces.AuditStream` to popular
third-party logging and observability systems.  All adapters treat their
upstream dependency as **optional** – an :class:`ImportError` is raised only
when the adapter is instantiated and the library is absent.

Available adapters
------------------

:class:`~airlog.adapters.logging_adapter.LoggingAdapter`
    Routes audit events through Python's standard :mod:`logging` module.

:class:`~airlog.adapters.opentelemetry_adapter.OpenTelemetryAdapter`
    Attaches audit events as span events on the active OpenTelemetry
    :class:`~opentelemetry.trace.Span`.

The existing :class:`~airlog.loguru_handler.LoguruAuditStream` continues to
be available at ``airlog.LoguruAuditStream`` for backward compatibility.
"""

from __future__ import annotations

from airlog.adapters.logging_adapter import LoggingAdapter
from airlog.adapters.ocsf_adapter import OcsfStream
from airlog.adapters.opentelemetry_adapter import OpenTelemetryAdapter

__all__ = [
    "LoggingAdapter",
    "OcsfStream",
    "OpenTelemetryAdapter",
]
