"""OCSF-native audit stream for airlog.

Emits each audit event as a newline-delimited OCSF JSON record to a
file-like sink (default: ``sys.stdout``).  Output can be piped into any
OCSF-aware SIEM, data lake, or log aggregator.

The OCSF class is auto-detected from the action by default:

* Login / logout / auth actions → **class 3002** (Authentication)
* User / account lifecycle actions → **class 3001** (Account Change)
* Everything else → **class 6003** (API Activity)

Pass *ocsf_class* explicitly to override the auto-detection.

Optional schema validation
--------------------------
Set ``validate=True`` and install ``ocsf-lib`` (``pip install airlog[ocsf]``)
to validate each event against the live OCSF schema before writing.  A
warning is printed for each missing required field; the event is still
written.

Example::

    import sys
    from airlog import OcsfStream, Principal
    from airlog.ocsf_support import OcsfClass, OcsfSeverity

    stream = OcsfStream(sink=sys.stdout, severity_id=OcsfSeverity.HIGH)
    stream.record(
        "login",
        principal=Principal(subject="alice", auth_method="password"),
        resource="session",
        resource_id="ses-001",
    )
    # → one line of OCSF JSON (class 3002 – Authentication) to stdout

    # Force a specific class:
    stream2 = OcsfStream(ocsf_class=OcsfClass.API_ACTIVITY)
    stream2.record("export", principal=..., resource="report")
"""

from __future__ import annotations

import json
import sys
import warnings
from typing import IO, Any

from airlog.interfaces import AuditEvent, AuditStream, HealthStatus, StreamFeature
from airlog.ocsf_support import (
    OCSF_SCHEMA_VERSION,
    OcsfClass,
    OcsfSeverity,
    build_ocsf_event,
    validate_ocsf_event,
)

__all__ = ["OcsfStream"]


class OcsfStream(AuditStream):
    """Audit stream that emits OCSF-formatted newline-delimited JSON.

    Each :meth:`~airlog.interfaces.AuditStream.record` call produces one
    JSON line on *sink* whose structure conforms to the OCSF schema version
    defined in :data:`~airlog.ocsf_support.OCSF_SCHEMA_VERSION`.

    Args:
        sink: Writable text-mode file object.  Defaults to ``sys.stdout``.
        ocsf_class: OCSF event class override.  ``None`` (default) lets
            :func:`~airlog.ocsf_support.detect_ocsf_class` pick the class
            from the action string.
        severity_id: OCSF ``severity_id`` applied to every event.  Defaults
            to :attr:`~airlog.ocsf_support.OcsfSeverity.INFORMATIONAL`
            (``1``).  Use :class:`~airlog.ocsf_support.OcsfSeverity` for
            named constants.
        validate: When ``True``, each event is validated against the OCSF
            schema via ``ocsf-lib`` before writing.  Missing required fields
            are emitted as :class:`UserWarning` warnings (the event is still
            written).  Requires ``pip install ocsf-lib``.
        schema_version: OCSF schema version used for validation.  Only
            relevant when *validate* is ``True``.  Defaults to
            :data:`~airlog.ocsf_support.OCSF_SCHEMA_VERSION`.

    Raises:
        ImportError: At construction time when *validate* is ``True`` and
            ``ocsf-lib`` is not installed.

    Example::

        stream = OcsfStream()
        stream.record(
            "login",
            principal=Principal(subject="bob", auth_method="jwt"),
            resource="session",
        )
    """

    def __init__(
        self,
        sink: IO[str] | None = None,
        ocsf_class: OcsfClass | None = None,
        severity_id: int = OcsfSeverity.INFORMATIONAL,
        validate: bool = False,
        schema_version: str = OCSF_SCHEMA_VERSION,
    ) -> None:
        if validate:
            try:
                import ocsf.util  # noqa: F401
            except ImportError as exc:
                raise ImportError(
                    "The 'ocsf-lib' package is required for OCSF schema validation. "
                    "Install it with: pip install ocsf-lib  (or: pip install airlog[ocsf])"
                ) from exc

        super().__init__()
        self._sink: IO[str] = sink if sink is not None else sys.stdout
        self._ocsf_class = ocsf_class
        self._severity_id = severity_id
        self._validate = validate
        self._schema_version = schema_version

    def emit(self, event: AuditEvent) -> None:
        """Serialize *event* as an OCSF JSON record and write it to the sink.

        Args:
            event: The audit event to emit.
        """
        ocsf_dict: dict[str, Any] = build_ocsf_event(
            event,
            ocsf_class=self._ocsf_class,
            severity_id=self._severity_id,
        )

        if self._validate:
            errors = validate_ocsf_event(ocsf_dict, schema_version=self._schema_version)
            for error in errors:
                warnings.warn(
                    f"OCSF validation: {error} (event_id={event.event_id})",
                    UserWarning,
                    stacklevel=2,
                )

        self._sink.write(json.dumps(ocsf_dict, default=str) + "\n")
        self._sink.flush()

    def health_check(self) -> HealthStatus:
        """Return healthy if the sink is writable."""
        try:
            writable = self._sink.writable()
        except Exception:
            writable = False
        return HealthStatus(
            healthy=writable,
            latency_ms=0.0,
            message="" if writable else "sink is not writable",
        )

    def supports_feature(self, feature: StreamFeature) -> bool:
        """Return ``False`` for all optional features."""
        return False
