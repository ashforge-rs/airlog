"""OCSF (Open Cybersecurity Schema Framework) support for airlog.

Provides the building blocks for producing OCSF-compliant event dictionaries
from :class:`~airlog.interfaces.AuditEvent` instances.

Supported OCSF classes
----------------------
* **3001** – Account Change (user / account lifecycle events)
* **3002** – Authentication (login, logout, SSO, MFA, …)
* **3004** – Entity Management (generic CRUD on IAM entities)
* **6003** – API Activity (default – general API operations)

Optional validation via ``ocsf-lib``
--------------------------------------
Install the optional ``ocsf-lib`` package to enable schema validation::

    pip install airlog[ocsf]

Then pass ``validate=True`` to :class:`~airlog.adapters.ocsf_adapter.OcsfStream`
or call :func:`validate_ocsf_event` directly.

References
----------
* OCSF schema browser: https://schema.ocsf.io
* ``ocsf-lib`` on PyPI: https://pypi.org/project/ocsf-lib/
"""

from __future__ import annotations

from enum import IntEnum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from airlog.interfaces import AuditEvent

__all__ = [
    "OCSF_SCHEMA_VERSION",
    "OcsfClass",
    "OcsfSeverity",
    "build_ocsf_event",
    "detect_ocsf_class",
    "validate_ocsf_event",
]

# OCSF schema version produced by airlog.
OCSF_SCHEMA_VERSION: str = "1.1.0"


# ---------------------------------------------------------------------------
# Public enumerations
# ---------------------------------------------------------------------------


class OcsfClass(IntEnum):
    """Supported OCSF event class UIDs.

    Use these values as the *ocsf_class* argument to
    :func:`build_ocsf_event` or
    :meth:`~airlog.adapters.ocsf_adapter.OcsfStream.__init__`.

    Members
    -------
    ACCOUNT_CHANGE (3001):
        User / account lifecycle events (create, delete, lock, password
        reset, …).
    AUTHENTICATION (3002):
        Login, logout, SSO, MFA, and other authentication events.
    ENTITY_MANAGEMENT (3004):
        Generic CRUD operations on IAM entities (roles, policies, groups).
    API_ACTIVITY (6003):
        General API operations – the safe default for most audit events.
    """

    ACCOUNT_CHANGE = 3001
    AUTHENTICATION = 3002
    ENTITY_MANAGEMENT = 3004
    API_ACTIVITY = 6003


class OcsfSeverity(IntEnum):
    """OCSF ``severity_id`` values (OCSF 1.1 §severity_id).

    Members
    -------
    UNKNOWN (0):
        The event severity is not known.
    INFORMATIONAL (1):
        Informational message.  No action required.
    LOW (2):
        Low-priority event requiring routine investigation.
    MEDIUM (3):
        Medium-priority event that requires attention.
    HIGH (4):
        High-priority event requiring immediate attention.
    CRITICAL (5):
        Critical event requiring urgent action.
    OTHER (99):
        Severity not covered by the standard values.
    """

    UNKNOWN = 0
    INFORMATIONAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5
    OTHER = 99


# ---------------------------------------------------------------------------
# Internal lookup tables
# ---------------------------------------------------------------------------

# Action keywords → OcsfClass (checked in order: ACCOUNT_CHANGE, AUTHENTICATION)
_ACCOUNT_KEYWORDS: frozenset[str] = frozenset(
    {
        "create_user",
        "delete_user",
        "update_user",
        "register_user",
        "enable_user",
        "disable_user",
        "lock_user",
        "unlock_user",
        "change_password",
        "reset_password",
        "password_change",
        "password_reset",
        "create_account",
        "delete_account",
        "update_account",
    }
)

_AUTH_KEYWORDS: frozenset[str] = frozenset(
    {
        "login",
        "logon",
        "logout",
        "logoff",
        "authenticate",
        "auth",
        "signin",
        "signout",
        "sign_in",
        "sign_out",
        "sso",
        "mfa",
        "totp",
        "authorize",
        "revoke_token",
    }
)

# activity_id for class 6003 - API Activity
_API_ACTIVITY_IDS: dict[str, int] = {
    "create": 1,
    "post": 1,
    "add": 1,
    "register": 1,
    "insert": 1,
    "read": 2,
    "get": 2,
    "list": 2,
    "describe": 2,
    "view": 2,
    "fetch": 2,
    "search": 2,
    "query": 2,
    "update": 3,
    "modify": 3,
    "patch": 3,
    "put": 3,
    "edit": 3,
    "change": 3,
    "delete": 4,
    "remove": 4,
    "destroy": 4,
    "purge": 4,
}

# activity_id for class 3002 - Authentication
_AUTH_ACTIVITY_IDS: dict[str, int] = {
    "login": 1,
    "logon": 1,
    "signin": 1,
    "sign_in": 1,
    "authenticate": 1,
    "auth": 1,
    "sso": 1,
    "mfa": 1,
    "totp": 1,
    "logout": 2,
    "logoff": 2,
    "signout": 2,
    "sign_out": 2,
}

# activity_id for class 3001 - Account Change
_ACCOUNT_ACTIVITY_IDS: dict[str, int] = {
    "create": 1,
    "create_user": 1,
    "create_account": 1,
    "register": 1,
    "register_user": 1,
    "enable": 2,
    "enable_user": 2,
    "change_password": 3,
    "password_change": 3,
    "reset_password": 4,
    "password_reset": 4,
    "disable": 5,
    "disable_user": 5,
    "delete": 6,
    "delete_user": 6,
    "delete_account": 6,
    "lock": 9,
    "lock_user": 9,
    "unlock": 10,
    "unlock_user": 10,
}

# activity_id for class 3004 - Entity Management
_ENTITY_ACTIVITY_IDS: dict[str, int] = {
    "create": 1,
    "post": 1,
    "add": 1,
    "read": 2,
    "get": 2,
    "list": 2,
    "describe": 2,
    "update": 3,
    "modify": 3,
    "patch": 3,
    "edit": 3,
    "delete": 4,
    "remove": 4,
}

_STATUS_IDS: dict[str, int] = {"success": 1, "failure": 2}

_SEVERITY_NAMES: dict[int, str] = {
    0: "Unknown",
    1: "Informational",
    2: "Low",
    3: "Medium",
    4: "High",
    5: "Critical",
    99: "Other",
}

_CATEGORY_INFO: dict[OcsfClass, tuple[int, str]] = {
    OcsfClass.ACCOUNT_CHANGE: (3, "Identity & Access Management"),
    OcsfClass.AUTHENTICATION: (3, "Identity & Access Management"),
    OcsfClass.ENTITY_MANAGEMENT: (3, "Identity & Access Management"),
    OcsfClass.API_ACTIVITY: (6, "Application Activity"),
}

_CLASS_NAMES: dict[OcsfClass, str] = {
    OcsfClass.ACCOUNT_CHANGE: "Account Change",
    OcsfClass.AUTHENTICATION: "Authentication",
    OcsfClass.ENTITY_MANAGEMENT: "Entity Management",
    OcsfClass.API_ACTIVITY: "API Activity",
}


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def detect_ocsf_class(action: str) -> OcsfClass:
    """Infer the most appropriate OCSF event class for *action*.

    Performs case-insensitive keyword matching against the action string.
    Account-change keywords are checked before authentication keywords so
    that actions like ``"create_user"`` resolve to
    :attr:`OcsfClass.ACCOUNT_CHANGE` rather than a default.

    Falls back to :attr:`OcsfClass.API_ACTIVITY` (6003) when no keyword
    matches.

    Args:
        action: The action string from an
            :class:`~airlog.interfaces.AuditEvent`.

    Returns:
        The most appropriate :class:`OcsfClass`.
    """
    normalized = action.lower().strip()
    if normalized in _ACCOUNT_KEYWORDS:
        return OcsfClass.ACCOUNT_CHANGE
    if normalized in _AUTH_KEYWORDS:
        return OcsfClass.AUTHENTICATION
    return OcsfClass.API_ACTIVITY


def _get_activity_id(action: str, ocsf_class: OcsfClass) -> int:
    """Return the OCSF ``activity_id`` for *action* within *ocsf_class*."""
    normalized = action.lower().strip()
    table: dict[str, int]
    if ocsf_class == OcsfClass.AUTHENTICATION:
        table = _AUTH_ACTIVITY_IDS
    elif ocsf_class == OcsfClass.ACCOUNT_CHANGE:
        table = _ACCOUNT_ACTIVITY_IDS
    elif ocsf_class == OcsfClass.ENTITY_MANAGEMENT:
        table = _ENTITY_ACTIVITY_IDS
    else:
        table = _API_ACTIVITY_IDS
    return table.get(normalized, 99)


def _build_metadata(event: AuditEvent) -> dict[str, Any]:
    """Build the OCSF ``metadata`` object for *event*."""
    return {
        "uid": event.event_id,
        "correlation_uid": event.correlation_id,
        "sequence": event.sequence,
        "log_provider": "airlog",
        "version": OCSF_SCHEMA_VERSION,
        "product": {
            "name": "airlog",
            "vendor_name": "airlog",
        },
    }


def build_ocsf_event(
    event: AuditEvent,
    ocsf_class: OcsfClass | None = None,
    severity_id: int = OcsfSeverity.INFORMATIONAL,
) -> dict[str, Any]:
    """Build an OCSF-compliant event dictionary from *event*.

    The returned dictionary conforms to OCSF schema version
    :data:`OCSF_SCHEMA_VERSION`.  Class-specific fields are populated
    according to the OCSF specification for the resolved class.

    Args:
        event: The source :class:`~airlog.interfaces.AuditEvent`.
        ocsf_class: Target OCSF class UID.  When ``None`` the class is
            inferred via :func:`detect_ocsf_class`.
        severity_id: OCSF ``severity_id``.  Use :class:`OcsfSeverity` for
            the named constants.  Defaults to
            :attr:`OcsfSeverity.INFORMATIONAL` (``1``).

    Returns:
        A plain Python :class:`dict` conforming to the OCSF schema.
    """
    if ocsf_class is None:
        ocsf_class = detect_ocsf_class(event.action)

    status_id = _STATUS_IDS.get(event.outcome, 0)
    activity_id = _get_activity_id(event.action, ocsf_class)
    category_uid, category_name = _CATEGORY_INFO[ocsf_class]

    base: dict[str, Any] = {
        "class_uid": int(ocsf_class),
        "class_name": _CLASS_NAMES[ocsf_class],
        "category_uid": category_uid,
        "category_name": category_name,
        "activity_id": activity_id,
        "activity_name": event.action,
        "type_uid": int(ocsf_class) * 100 + activity_id,
        "time": event.timestamp_ns // 1_000_000,  # OCSF uses milliseconds
        "severity_id": severity_id,
        "severity": _SEVERITY_NAMES.get(severity_id, "Other"),
        "status": event.outcome,
        "status_id": status_id,
        "cloud": {},  # required by OCSF; callers may enrich via context
        "src_endpoint": {"ip": event.context.get("ip", "")},
        "metadata": _build_metadata(event),
        "raw_data": event.checksum,
        "unmapped": event.context,
    }

    if ocsf_class == OcsfClass.AUTHENTICATION:
        base["user"] = {
            "name": event.principal.subject,
            "type": "User",
        }
        base["actor"] = {
            "idp": {"name": event.principal.auth_method},
        }
        if event.resource:
            base["resources"] = [{"type": event.resource, "uid": event.resource_id}]

    elif ocsf_class == OcsfClass.ACCOUNT_CHANGE:
        base["user"] = {
            "name": event.principal.subject,
            "type": "User",
        }
        base["actor"] = {
            "user": {"name": event.principal.subject, "type": "User"},
            "idp": {"name": event.principal.auth_method},
        }
        base["resources"] = [{"type": event.resource, "uid": event.resource_id}]

    elif ocsf_class == OcsfClass.ENTITY_MANAGEMENT:
        base["actor"] = {
            "user": {
                "name": event.principal.subject,
                "type": "User",
            },
            "idp": {
                "name": event.principal.auth_method,
            },
        }
        base["entity"] = {
            "type": event.resource,
            "uid": event.resource_id,
            "name": event.resource,
        }
        base["api"] = {
            "operation": event.action,
            "response": {
                "code": 200 if event.outcome == "success" else 500,
                "message": event.outcome,
            },
        }
        base["resources"] = [{"type": event.resource, "uid": event.resource_id}]

    else:  # API_ACTIVITY
        base["actor"] = {
            "user": {
                "name": event.principal.subject,
                "type": "User",
            },
            "idp": {
                "name": event.principal.auth_method,
            },
        }
        base["api"] = {
            "operation": event.action,
            "response": {
                "code": 200 if event.outcome == "success" else 500,
                "message": event.outcome,
            },
        }
        base["resources"] = [{"type": event.resource, "uid": event.resource_id}]

    return base


# ---------------------------------------------------------------------------
# Optional validation via ocsf-lib
# ---------------------------------------------------------------------------

_schema_cache: dict[str, Any] = {}


def validate_ocsf_event(
    event_dict: dict[str, Any],
    schema_version: str = OCSF_SCHEMA_VERSION,
) -> list[str]:
    """Validate *event_dict* against the live OCSF schema using ``ocsf-lib``.

    Checks that all ``required`` attributes defined in the OCSF schema for
    the event's ``class_uid`` are present in *event_dict*.  The schema is
    fetched from ``schema.ocsf.io`` on the first call and cached in memory
    for subsequent calls.

    Requires the ``ocsf-lib`` package::

        pip install ocsf-lib
        # or
        pip install airlog[ocsf]

    Args:
        event_dict: OCSF event dictionary to validate (e.g. from
            :func:`build_ocsf_event`).
        schema_version: OCSF schema version to validate against.  Defaults
            to :data:`OCSF_SCHEMA_VERSION`.

    Returns:
        A list of validation error strings.  An empty list means all
        required fields are present.

    Raises:
        ImportError: When the ``ocsf-lib`` package is not installed.
    """
    try:
        from ocsf.util import get_schema as _get_schema
    except ImportError as exc:
        raise ImportError(
            "The 'ocsf-lib' package is required for OCSF schema validation. "
            "Install it with: pip install ocsf-lib  (or: pip install airlog[ocsf])"
        ) from exc

    if schema_version not in _schema_cache:
        _schema_cache[schema_version] = _get_schema(schema_version)

    schema = _schema_cache[schema_version]
    class_uid: int = event_dict.get("class_uid", -1)

    event_class = next(
        (cls for cls in schema.classes.values() if cls.uid == class_uid),
        None,
    )
    if event_class is None:
        return [f"Unknown class_uid: {class_uid}"]

    errors: list[str] = []
    if event_class.attributes:
        for attr_name, attr in event_class.attributes.items():
            if attr.requirement == "required" and attr_name not in event_dict:
                errors.append(
                    f"Missing required field '{attr_name}' "
                    f"for OCSF class {class_uid} ({_CLASS_NAMES.get(OcsfClass(class_uid), '?')})"
                )

    return errors
