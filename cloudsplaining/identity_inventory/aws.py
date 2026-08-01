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
from typing import TYPE_CHECKING, Any

from cloudsplaining.identity_inventory.classify import is_machine_name
from cloudsplaining.identity_inventory.model import HUMAN, MACHINE, IdentityRecord
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
    creators = _creators(data.get("cloudTrailEvents") or [])
    report = _credential_report_index(data.get("credentialReport"))
    records: list[IdentityRecord] = []
    for user in data.get("UserDetailList") or []:
        records.append(_user_record(user, report, creators))
        records.extend(_access_key_records(user, report))
    records += [_role_record(role, creators) for role in data.get("RoleDetailList") or []]
    return records


# ------------------------------------------------------------------------ users
def _user_record(
    user: dict[str, Any],
    report: dict[str, dict[str, Any]],
    creators: dict[tuple[str, str], str],
) -> IdentityRecord:
    name = user.get("UserName") or ""
    arn = user.get("Arn") or ""
    report_row = report.get(name) or report.get(arn)
    return IdentityRecord(
        provider=PROVIDER,
        identity_type="user",
        id=arn or user.get("UserId") or name,
        name=name,
        classification=MACHINE if _is_machine_user(name, report_row) else HUMAN,
        created_at=parse_timestamp(user.get("CreateDate")),
        last_used=_user_last_used(user, report_row),
        created_by=creators.get(("user", name)),
    )


def _is_machine_user(name: str, report_row: dict[str, Any] | None) -> bool:
    """A user is a machine when named like one, or shaped like one: active access
    keys with neither a console password nor MFA (nobody logs in as it)."""
    if is_machine_name(name):
        return True
    if report_row is None:
        return False
    if _report_flag(report_row, "password_enabled") or _report_flag(report_row, "mfa_active"):
        return False
    return _report_flag(report_row, "access_key_1_active") or _report_flag(report_row, "access_key_2_active")


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


# ------------------------------------------------------------------------ roles
def _role_record(role: dict[str, Any], creators: dict[tuple[str, str], str]) -> IdentityRecord:
    name = role.get("RoleName") or ""
    return IdentityRecord(
        provider=PROVIDER,
        identity_type="role",
        id=role.get("Arn") or role.get("RoleId") or name,
        name=name,
        classification=HUMAN if _is_sso_role(role) else MACHINE,
        created_at=parse_timestamp(role.get("CreateDate")),
        last_used=parse_timestamp((role.get("RoleLastUsed") or {}).get("LastUsedDate")),
        created_by=creators.get(("role", name)),
    )


def _is_sso_role(role: dict[str, Any]) -> bool:
    """Roles assumed by people via SAML federation; every other role is a workload."""
    path = role.get("Path") or ""
    if "/aws-service-role/" in path or "/aws-service-role/" in (role.get("Arn") or ""):
        return False
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
def _creators(events: list[dict[str, Any]]) -> dict[tuple[str, str], str]:
    """Map ("user"|"role", name) -> creator principal from CreateUser/CreateRole events."""
    creators: dict[tuple[str, str], str] = {}
    for item in events:
        event = _event_payload(item)
        if event is None:
            continue
        identity = event.get("userIdentity") or {}
        creator = identity.get("arn") or identity.get("userName") or identity.get("principalId")
        if not creator:
            continue
        parameters = event.get("requestParameters") or {}
        event_name = event.get("eventName") or event.get("EventName")
        if event_name == "CreateUser" and parameters.get("userName"):
            creators["user", parameters["userName"]] = creator
        elif event_name == "CreateRole" and parameters.get("roleName"):
            creators["role", parameters["roleName"]] = creator
    return creators


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
