"""AWS identity lifecycle inventory.

Input is the ``aws iam get-account-authorization-details`` JSON — the same file
the main scan consumes. Optional enrichment keys on the same dict:

- ``credentialReport``: the decoded ``aws iam get-credential-report`` CSV text
  (or its rows as a list of dicts) — fills user ``last_used`` from password and
  access-key usage.
- ``cloudTrailEvents``: ``aws cloudtrail lookup-events`` items, either raw
  (with the stringified ``CloudTrailEvent`` payload) or already parsed — fills
  ``created_by`` from ``CreateUser`` / ``CreateRole`` events.
"""

# Copyright (c) 2020, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
from __future__ import annotations

import csv
import io
import json
import urllib.parse
from operator import itemgetter
from typing import TYPE_CHECKING, Any

from cloudsplaining.identity_inventory.classify import machine_name_signal, resolve
from cloudsplaining.identity_inventory.model import HUMAN, MACHINE, UNKNOWN, IdentityRecord
from cloudsplaining.identity_inventory.parsing import as_bool, max_timestamp, parse_timestamp

if TYPE_CHECKING:
    from datetime import datetime

PROVIDER = "aws"

_LAST_USED_REPORT_COLUMNS = ("password_last_used", "access_key_1_last_used_date", "access_key_2_last_used_date")


def build_inventory(data: dict[str, Any]) -> list[IdentityRecord]:
    """Inventory every IAM user and role in an authorization-details snapshot.

    When a credential report is attached, each existing access key also becomes a
    child ``access_key`` record whose ``created_by`` is the owning user — structural
    attribution that, unlike audit logs, never expires.
    """
    events = data.get("cloudTrailEvents") or []
    creators = _creators(events)
    credential_events = _credential_event_flags(events)
    report = _credential_report_index(data.get("credentialReport"))
    report_available = bool(data.get("credentialReport"))
    report_generated_at = parse_timestamp(data.get("credentialReportGeneratedTime"))
    supplement = data.get("credentialSupplement") or {}
    records: list[IdentityRecord] = []
    for user in data.get("UserDetailList") or []:
        records.append(
            _user_record(
                user,
                report,
                report_available,
                report_generated_at,
                supplement,
                credential_events,
                creators,
            )
        )
        records.extend(_access_key_records(user, report))
    records += [_role_record(role, creators) for role in data.get("RoleDetailList") or []]
    return records


# ------------------------------------------------------------------------ users
def _user_record(
    user: dict[str, Any],
    report: dict[str, dict[str, Any]],
    report_available: bool,
    report_generated_at: datetime | None,
    supplement: dict[str, dict[str, Any]],
    credential_events: dict[str, dict[str, bool]],
    creators: dict[tuple[str, str], list[tuple[datetime | None, str]]],
) -> IdentityRecord:
    name = user.get("UserName") or ""
    arn = user.get("Arn") or ""
    report_row = report.get(name) or report.get(arn)
    created_at = parse_timestamp(user.get("CreateDate"))
    classification, reason = _user_classification(
        name,
        created_at,
        report_row,
        report_available,
        report_generated_at,
        supplement.get(name),
        credential_events.get(name),
    )
    return IdentityRecord(
        provider=PROVIDER,
        identity_type="user",
        id=arn or user.get("UserId") or name,
        name=name,
        classification=classification,
        classification_reason=reason,
        created_at=created_at,
        last_used=_user_last_used(user, report_row),
        created_by=_creator_for(creators, ("user", name), created_at),
    )


def _user_classification(
    name: str,
    created_at: datetime | None,
    report_row: dict[str, Any] | None,
    report_available: bool,
    report_generated_at: datetime | None,
    supplement_row: dict[str, Any] | None,
    event_flags: dict[str, bool] | None,
) -> tuple[str, str]:
    """Machine-name → live supplement → credential report → CloudTrail credential
    events → honest unknown; the first present evidence wins."""
    fallback = _missing_credential_evidence_reason(report_available, created_at, report_generated_at)
    return resolve(
        machine_name_signal(name),
        _shape_signal(_supplement_shape(supplement_row), "live IAM lookup"),
        _shape_signal(_report_shape(report_row), "credential report"),
        _events_signal(event_flags),
        fallback=fallback,
    )


def _missing_credential_evidence_reason(
    report_available: bool,
    created_at: datetime | None,
    report_generated_at: datetime | None,
) -> str:
    """Describe a missing report row without asserting an unverified cache race."""
    if not report_available:
        return "no credential evidence: credential report unavailable"
    if report_generated_at is None:
        return "credential report row missing; generation time unavailable"
    if created_at is None:
        return "credential report row missing; user creation time unavailable"
    if created_at > report_generated_at:
        return "created after credential report was generated"
    return "credential report row missing for pre-existing user"


def _supplement_shape(row: dict[str, Any] | None) -> dict[str, Any] | None:
    """Shape from a live-lookup supplement row; needs both authoritative fields."""
    if not row or "has_login_profile" not in row or "access_keys_active" not in row:
        return None
    return {
        "has_password": bool(row["has_login_profile"]),
        "has_mfa": bool(row.get("mfa_devices") or 0),
        "active_keys": int(row["access_keys_active"] or 0),
    }


def _report_shape(report_row: dict[str, Any] | None) -> dict[str, Any] | None:
    if report_row is None:
        return None
    active_keys = sum(1 for slot in (1, 2) if _report_flag(report_row, f"access_key_{slot}_active"))
    return {
        "has_password": _report_flag(report_row, "password_enabled"),
        "has_mfa": _report_flag(report_row, "mfa_active"),
        "active_keys": active_keys,
    }


def _shape_signal(shape: dict[str, Any] | None, source: str) -> tuple[str, str] | None:
    """Classify a credential shape: password/MFA → human, keys-only → machine, nothing → unknown."""
    if shape is None:
        return None
    if shape["has_password"] or shape["has_mfa"]:
        return (HUMAN, f"console password or MFA ({source})")
    if shape["active_keys"]:
        return (MACHINE, f"active access keys, no console password ({source})")
    return (UNKNOWN, f"no credentials provisioned ({source})")


def _report_flag(row: dict[str, Any], column: str) -> bool:
    return as_bool(row.get(column))


def _access_key_records(user: dict[str, Any], report: dict[str, dict[str, Any]]) -> list[IdentityRecord]:
    name = user.get("UserName") or ""
    arn = user.get("Arn") or ""
    report_row = report.get(name) or report.get(arn)
    if not report_row:
        return []
    records = []
    for slot in (1, 2):
        rotated = parse_timestamp(report_row.get(f"access_key_{slot}_last_rotated"))
        # A key slot exists when it was ever rotated (created) or is currently active.
        if rotated is None and not _report_flag(report_row, f"access_key_{slot}_active"):
            continue
        records.append(
            IdentityRecord(
                provider=PROVIDER,
                identity_type="access_key",
                id=f"{arn or name}/access-key-{slot}",
                name=f"{name}/access-key-{slot}",
                classification=MACHINE,
                classification_reason="access key",
                created_at=rotated,
                last_used=parse_timestamp(report_row.get(f"access_key_{slot}_last_used_date")),
                created_by=arn or name,
            )
        )
    return records


def _user_last_used(user: dict[str, Any], report_row: dict[str, Any] | None) -> datetime | None:
    candidates = [user.get("PasswordLastUsed")]
    if report_row:
        candidates.extend(report_row.get(column) for column in _LAST_USED_REPORT_COLUMNS)
    return max_timestamp(*candidates)


def _credential_report_index(raw: str | list[dict[str, Any]] | None) -> dict[str, dict[str, Any]]:
    """Index credential-report rows (CSV text or list of dicts) by user name and ARN."""
    if not raw:
        return {}
    rows = csv.DictReader(io.StringIO(raw)) if isinstance(raw, str) else raw
    index: dict[str, dict[str, Any]] = {}
    for row in rows:
        for key in (row.get("user"), row.get("arn")):
            if key:
                index[key] = row
    return index


_CREDENTIAL_EVENT_NAMES = ("CreateAccessKey", "CreateLoginProfile")


def _credential_event_flags(events: list[dict[str, Any]]) -> dict[str, dict[str, bool]]:
    """Map user name -> which credential-creation events CloudTrail saw for them."""
    flags: dict[str, dict[str, bool]] = {}
    for item in events:
        event = _event_payload(item)
        if event is None:
            continue
        event_name = event.get("eventName") or event.get("EventName")
        if event_name not in _CREDENTIAL_EVENT_NAMES:
            continue
        parameters = event.get("requestParameters") or {}
        response = event.get("responseElements") or {}
        user = parameters.get("userName") or (response.get("accessKey") or {}).get("userName")
        if not user:
            continue
        key = "access_key_created" if event_name == "CreateAccessKey" else "login_profile_created"
        flags.setdefault(user, {})[key] = True
    return flags


def _events_signal(flags: dict[str, bool] | None) -> tuple[str, str] | None:
    """Credential-creation events are corroborating evidence for report-gap users."""
    if not flags:
        return None
    if flags.get("login_profile_created"):
        return (HUMAN, "console login profile created (CloudTrail events)")
    if flags.get("access_key_created"):
        return (MACHINE, "access key created, no console password (CloudTrail events)")
    return None


# ------------------------------------------------------------------------ roles
def _role_record(
    role: dict[str, Any],
    creators: dict[tuple[str, str], list[tuple[datetime | None, str]]],
) -> IdentityRecord:
    name = role.get("RoleName") or ""
    if _is_service_role(role):
        classification, reason = MACHINE, "AWS service role"
    elif _is_identity_center_role(role):
        classification, reason = HUMAN, "IAM Identity Center role"
    elif _is_sso_role(role):
        classification, reason = HUMAN, "SAML-federated role"
    else:
        classification, reason = MACHINE, "workload role"
    created_at = parse_timestamp(role.get("CreateDate"))
    return IdentityRecord(
        provider=PROVIDER,
        identity_type="role",
        id=role.get("Arn") or role.get("RoleId") or name,
        name=name,
        classification=classification,
        classification_reason=reason,
        created_at=created_at,
        last_used=parse_timestamp((role.get("RoleLastUsed") or {}).get("LastUsedDate")),
        created_by=_creator_for(creators, ("role", name), created_at),
    )


def _is_service_role(role: dict[str, Any]) -> bool:
    path = role.get("Path") or ""
    return "/aws-service-role/" in path or "/aws-service-role/" in (role.get("Arn") or "")


def _is_identity_center_role(role: dict[str, Any]) -> bool:
    """AWS IAM Identity Center permission-set roles are used by people."""
    path = role.get("Path") or ""
    arn = role.get("Arn") or ""
    name = role.get("RoleName") or ""
    return (
        "/aws-reserved/sso.amazonaws.com/" in path
        or "/aws-reserved/sso.amazonaws.com/" in arn
        or name.startswith("AWSReservedSSO_")
    )


def _is_sso_role(role: dict[str, Any]) -> bool:
    """Roles assumed by people via SAML federation; every other role is a workload."""
    for statement in _trust_statements(role):
        actions = statement.get("Action") or []
        if isinstance(actions, str):
            actions = [actions]
        if "sts:AssumeRoleWithSAML" in actions:
            return True
        principal = statement.get("Principal")
        federated = principal.get("Federated") if isinstance(principal, dict) else None
        federated_values = [federated] if isinstance(federated, str) else list(federated or [])
        if any(":saml-provider/" in value for value in federated_values):
            return True
    return False


def _trust_statements(role: dict[str, Any]) -> list[dict[str, Any]]:
    document = role.get("AssumeRolePolicyDocument")
    if isinstance(document, str):
        # The raw IAM API returns the trust policy URL-encoded.
        try:
            document = json.loads(urllib.parse.unquote(document))
        except ValueError:
            return []
    if not isinstance(document, dict):
        return []
    statements = document.get("Statement") or []
    if isinstance(statements, dict):
        statements = [statements]
    return [statement for statement in statements if isinstance(statement, dict)]


# ------------------------------------------------------------------- created_by
_CREATION_EVENT_TOLERANCE_SECONDS = 10 * 60


def _creators(events: list[dict[str, Any]]) -> dict[tuple[str, str], list[tuple[datetime | None, str]]]:
    """Map an identity key to timestamped creator candidates from CloudTrail."""
    creators: dict[tuple[str, str], list[tuple[datetime | None, str]]] = {}
    for item in events:
        event = _event_payload(item)
        if event is None:
            continue
        identity = event.get("userIdentity") or {}
        creator = identity.get("arn") or identity.get("userName") or identity.get("principalId")
        if not creator:
            continue
        event_time = parse_timestamp(event.get("eventTime") or event.get("EventTime") or item.get("EventTime"))
        parameters = event.get("requestParameters") or {}
        event_name = event.get("eventName") or event.get("EventName")
        if event_name == "CreateUser" and parameters.get("userName"):
            creators.setdefault(("user", parameters["userName"]), []).append((event_time, creator))
        elif event_name == "CreateRole" and parameters.get("roleName"):
            creators.setdefault(("role", parameters["roleName"]), []).append((event_time, creator))
        elif event_name == "CreateServiceLinkedRole":
            # The request only names the service; the created role is in the response.
            role = (event.get("responseElements") or {}).get("role") or {}
            if role.get("roleName"):
                creators.setdefault(("role", role["roleName"]), []).append((event_time, creator))
    return creators


def _creator_for(
    creators: dict[tuple[str, str], list[tuple[datetime | None, str]]],
    key: tuple[str, str],
    created_at: datetime | None,
) -> str | None:
    """Choose the creation event for the current incarnation, not a namesake."""
    candidates = creators.get(key) or []
    timed = [(stamp, actor) for stamp, actor in candidates if stamp is not None]
    if created_at is not None and timed:
        stamp, actor = min(timed, key=lambda item: abs((item[0] - created_at).total_seconds()))
        if abs((stamp - created_at).total_seconds()) <= _CREATION_EVENT_TOLERANCE_SECONDS:
            return actor
        return None
    if timed:
        return max(timed, key=itemgetter(0))[1]
    return candidates[0][1] if candidates else None


def _event_payload(item: dict[str, Any]) -> dict[str, Any] | None:
    payload = item.get("CloudTrailEvent")
    if payload is None:
        return item
    if not isinstance(payload, str):
        return payload if isinstance(payload, dict) else None
    try:
        parsed = json.loads(payload)
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None
