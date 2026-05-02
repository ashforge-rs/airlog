"""Metrics-instrumented audit stream wrapper.

:class:`MetricsAuditStream` wraps any :class:`~airlog.interfaces.AuditStream`
backend and records per-event instrumentation using only stdlib primitives
(:mod:`time`, :mod:`threading`, :mod:`collections`).  No third-party packages
are required.

Collected metrics are exposed via :meth:`~MetricsAuditStream.get_metrics`,
which returns a flat dictionary whose keys follow a Prometheus/OpenTelemetry
naming convention so they can be scraped without transformation.

Example::

    from airlog.metrics import MetricsAuditStream
    from airlog.adapters import LoggingAdapter

    backend = LoggingAdapter()
    instrumented = MetricsAuditStream(backend)
    instrumented.record("login", principal=p, resource="session")

    stats = instrumented.get_metrics()
    print(stats["emit_total"])          # number of successful emits
    print(stats["emit_error_total"])    # number of failed emits
    print(stats["emit_latency_p99_ms"]) # 99th-percentile emit latency
"""

from __future__ import annotations

import threading
import time
from typing import Any

from airlog.interfaces import AuditEvent, AuditStream, HealthStatus, StreamFeature

__all__ = ["MetricsAuditStream"]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Maximum number of latency samples retained for histogram computation.
#: Older entries are evicted when the ring-buffer wraps.
_MAX_SAMPLES: int = 10_000


# ---------------------------------------------------------------------------
# MetricsAuditStream
# ---------------------------------------------------------------------------


class MetricsAuditStream(AuditStream):
    """An :class:`~airlog.interfaces.AuditStream` decorator that records metrics.

    Wraps a single *backend* stream and intercepts every :meth:`emit` /
    :meth:`aemit` call to track:

    * **emit_total** – cumulative count of successful emits.
    * **emit_error_total** – cumulative count of failed emits (exceptions raised
      by the backend).
    * **emit_latency_ms** – per-call round-trip duration (histogram samples).
    * **queue_depth** – number of in-flight concurrent :meth:`emit` calls at
      the moment :meth:`get_metrics` is read.

    All counters are thread-safe (protected by a :class:`threading.Lock`).

    Args:
        backend: The :class:`~airlog.interfaces.AuditStream` to wrap.

    Example::

        metrics_stream = MetricsAuditStream(LoggingAdapter())
        metrics_stream.record("delete", principal=p, resource="doc")
        print(metrics_stream.get_metrics())
    """

    def __init__(self, backend: AuditStream) -> None:
        super().__init__()
        self._backend = backend
        self._lock = threading.Lock()
        self._emit_total: int = 0
        self._emit_error_total: int = 0
        self._queue_depth: int = 0
        # Ring-buffer of latency samples (milliseconds, float)
        self._latency_samples: list[float] = []

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _record_success(self, latency_ms: float) -> None:
        with self._lock:
            self._emit_total += 1
            self._latency_samples.append(latency_ms)
            if len(self._latency_samples) > _MAX_SAMPLES:
                # Evict the oldest entry (O(n) but rare; ring-buffer semantics)
                self._latency_samples = self._latency_samples[-_MAX_SAMPLES:]

    def _record_error(self, latency_ms: float) -> None:
        with self._lock:
            self._emit_error_total += 1
            self._latency_samples.append(latency_ms)
            if len(self._latency_samples) > _MAX_SAMPLES:
                self._latency_samples = self._latency_samples[-_MAX_SAMPLES:]

    @staticmethod
    def _percentile(samples: list[float], pct: float) -> float:
        """Return the *pct*-th percentile of *samples* (0–100).

        Returns 0.0 when *samples* is empty.
        """
        if not samples:
            return 0.0
        sorted_s = sorted(samples)
        idx = max(0, int(len(sorted_s) * pct / 100) - 1)
        return sorted_s[idx]

    # ------------------------------------------------------------------
    # AuditStream interface
    # ------------------------------------------------------------------

    def emit(self, event: AuditEvent) -> None:
        """Emit *event* through the wrapped backend, recording metrics.

        Args:
            event: The audit event to emit.

        Raises:
            Exception: Re-raises any exception thrown by the backend after
                incrementing :attr:`emit_error_total`.
        """
        with self._lock:
            self._queue_depth += 1
        start = time.monotonic()
        try:
            self._backend.emit(event)
            latency_ms = (time.monotonic() - start) * 1_000
            self._record_success(latency_ms)
        except Exception:
            latency_ms = (time.monotonic() - start) * 1_000
            self._record_error(latency_ms)
            raise
        finally:
            with self._lock:
                self._queue_depth -= 1

    async def aemit(self, event: AuditEvent) -> bool:
        """Asynchronously emit *event*, recording metrics.

        Args:
            event: The audit event to emit.

        Returns:
            ``True`` when the backend accepted the event, ``False`` on error.
        """
        with self._lock:
            self._queue_depth += 1
        start = time.monotonic()
        try:
            result = await self._backend.aemit(event)
            latency_ms = (time.monotonic() - start) * 1_000
            self._record_success(latency_ms)
            return result
        except Exception:
            latency_ms = (time.monotonic() - start) * 1_000
            self._record_error(latency_ms)
            return False
        finally:
            with self._lock:
                self._queue_depth -= 1

    def health_check(self) -> HealthStatus:
        """Delegate to the wrapped backend's :meth:`~AuditStream.health_check`.

        Returns:
            The backend's :class:`~airlog.interfaces.HealthStatus`.
        """
        return self._backend.health_check()

    def supports_feature(self, feature: StreamFeature) -> bool:
        """Delegate to the wrapped backend's :meth:`~AuditStream.supports_feature`.

        Args:
            feature: The feature to query.

        Returns:
            ``True`` if the backend advertises support for *feature*.
        """
        return self._backend.supports_feature(feature)

    # ------------------------------------------------------------------
    # Metrics API
    # ------------------------------------------------------------------

    def get_metrics(self) -> dict[str, Any]:
        """Return a snapshot of all collected metrics.

        The dictionary is safe to serialise to JSON or forward to a Prometheus
        exporter without transformation.  Percentile keys follow the naming
        convention ``emit_latency_p<NN>_ms``.

        Returns:
            A ``dict`` with the following keys:

            ``emit_total``
                Total number of successful :meth:`emit` calls.
            ``emit_error_total``
                Total number of :meth:`emit` calls that raised an exception.
            ``emit_latency_min_ms``
                Minimum observed emit latency in milliseconds (``0.0`` if none).
            ``emit_latency_max_ms``
                Maximum observed emit latency in milliseconds (``0.0`` if none).
            ``emit_latency_mean_ms``
                Arithmetic mean emit latency in milliseconds (``0.0`` if none).
            ``emit_latency_p50_ms``
                50th-percentile (median) emit latency in milliseconds.
            ``emit_latency_p95_ms``
                95th-percentile emit latency in milliseconds.
            ``emit_latency_p99_ms``
                99th-percentile emit latency in milliseconds.
            ``emit_sample_count``
                Number of latency samples retained (up to ``10 000``).
            ``queue_depth``
                Number of in-flight concurrent emit calls at snapshot time.
            ``error_rate``
                Fraction of calls that errored: ``emit_error_total /
                (emit_total + emit_error_total)`` in ``[0.0, 1.0]``.
        """
        with self._lock:
            total = self._emit_total
            errors = self._emit_error_total
            depth = self._queue_depth
            samples = list(self._latency_samples)

        call_total = total + errors
        error_rate = errors / call_total if call_total > 0 else 0.0
        mean_ms = sum(samples) / len(samples) if samples else 0.0

        return {
            "emit_total": total,
            "emit_error_total": errors,
            "emit_latency_min_ms": min(samples) if samples else 0.0,
            "emit_latency_max_ms": max(samples) if samples else 0.0,
            "emit_latency_mean_ms": mean_ms,
            "emit_latency_p50_ms": self._percentile(samples, 50),
            "emit_latency_p95_ms": self._percentile(samples, 95),
            "emit_latency_p99_ms": self._percentile(samples, 99),
            "emit_sample_count": len(samples),
            "queue_depth": depth,
            "error_rate": error_rate,
        }

    def reset_metrics(self) -> None:
        """Reset all counters and latency samples to zero.

        Useful in tests or after a rolling reset window.
        """
        with self._lock:
            self._emit_total = 0
            self._emit_error_total = 0
            self._queue_depth = 0
            self._latency_samples = []
