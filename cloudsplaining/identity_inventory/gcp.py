"""GCP identity lifecycle inventory.

Input is the GCP collector snapshot (``serviceAccounts``, ``bindings``) plus,
optionally:

- ``users``: a Workspace / Cloud Identity directory export
  (Admin SDK ``users.list``) — human users with ``creationTime`` /
  ``lastLoginTime``.
- ``auditLogEntries``: Admin Activity log entries — fills service-account
  ``created_at`` / ``created_by`` from ``CreateServiceAccount`` calls.
- ``serviceAccountActivities``: Policy Analyzer
  ``serviceAccountLastAuthentication`` activities — fills service-account
  ``last_used``.

Human principals that only appear as ``user:`` binding members are inventoried
with unknown lifecycle fields rather than dropped.
"""

# Copyright (c) 2020, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from cloudsplaining.identity_inventory.classify import is_machine_name
from cloudsplaining.identity_inventory.model import HUMAN, MACHINE, IdentityRecord
from cloudsplaining.identity_inventory.parsing import get_field, parse_timestamp

PROVIDER = "gcp"

#: Workspace exports report "never logged in" as the Unix epoch.
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def build_inventory(data: dict[str, Any]) -> list[IdentityRecord]:
    """Inventory service accounts and human users; groups/domains are not identities."""
    sa_audit = _sa_audit(data.get("auditLogEntries") or [])
    activities = _sa_activities(data.get("serviceAccountActivities") or [])

    records: list[IdentityRecord] = []
    seen: set[str] = set()
    for sa in data.get("serviceAccounts") or []:
        email = get_field(sa, "email") or ""
        records.append(_sa_record(sa, sa_audit, activities))
        seen.add(email)
    for user in data.get("users") or []:
        email = get_field(user, "primaryEmail") or ""
        records.append(_user_record(user))
        seen.add(email)
    for member_type, email in _binding_members(data.get("bindings") or []):
        if email in seen:
            continue
        seen.add(email)
        if member_type == "service_account":
            records.append(_sa_record({"email": email}, sa_audit, activities))
        else:
            records.append(_member_user_record(email))
    return records


# --------------------------------------------------------------- service accounts
def _sa_record(
    sa: dict[str, Any],
    sa_audit: dict[str, tuple[Any, str | None]],
    activities: dict[str, Any],
) -> IdentityRecord:
    email = get_field(sa, "email") or ""
    audit_time, audit_actor = sa_audit.get(email, (None, None))
    return IdentityRecord(
        provider=PROVIDER,
        identity_type="service_account",
        id=get_field(sa, "uniqueId") or email,
        name=email,
        classification=MACHINE,
        created_at=parse_timestamp(get_field(sa, "createTime")) or parse_timestamp(audit_time),
        last_used=parse_timestamp(activities.get(email)),
        created_by=audit_actor,
    )


def _sa_audit(entries: list[dict[str, Any]]) -> dict[str, tuple[Any, str | None]]:
    """Map service-account email -> (creation timestamp, creator principal)."""
    audit: dict[str, tuple[Any, str | None]] = {}
    for entry in entries:
        payload = get_field(entry, "protoPayload") or {}
        method = get_field(payload, "methodName") or ""
        if not method.endswith("CreateServiceAccount"):
            continue
        email = get_field(get_field(payload, "response") or {}, "email")
        if not email:
            continue
        actor = get_field(get_field(payload, "authenticationInfo") or {}, "principalEmail")
        audit[email] = (get_field(entry, "timestamp") or get_field(entry, "receiveTimestamp"), actor)
    return audit


def _sa_activities(activities: list[dict[str, Any]]) -> dict[str, Any]:
    """Map service-account email -> lastAuthenticatedTime from Policy Analyzer."""
    last_auth: dict[str, Any] = {}
    for activity in activities:
        detail = get_field(activity, "activity") or {}
        email = get_field(get_field(detail, "serviceAccount") or {}, "email")
        if not email:
            full_name = get_field(activity, "fullResourceName") or ""
            email = full_name.rsplit("/", 1)[-1] if "@" in full_name else ""
        if email:
            last_auth[email] = get_field(detail, "lastAuthenticatedTime")
    return last_auth


# ------------------------------------------------------------------------- users
def _user_record(user: dict[str, Any]) -> IdentityRecord:
    email = get_field(user, "primaryEmail") or ""
    last_login = parse_timestamp(get_field(user, "lastLoginTime"))
    if last_login == _EPOCH:
        last_login = None
    return IdentityRecord(
        provider=PROVIDER,
        identity_type="user",
        id=user.get("id") or email,
        name=email,
        classification=MACHINE if is_machine_name(email) else HUMAN,
        created_at=parse_timestamp(get_field(user, "creationTime")),
        last_used=last_login,
    )


def _member_user_record(email: str) -> IdentityRecord:
    return IdentityRecord(
        provider=PROVIDER,
        identity_type="user",
        id=email,
        name=email,
        classification=MACHINE if is_machine_name(email) else HUMAN,
    )


def _binding_members(bindings: list[dict[str, Any]]) -> list[tuple[str, str]]:
    """Yield ("user"|"service_account", email) pairs; other member kinds are skipped."""
    members: list[tuple[str, str]] = []
    for binding in bindings:
        for member in binding.get("members") or []:
            kind, _, principal = str(member).partition(":")
            if kind == "user" and principal:
                members.append(("user", principal))
            elif kind == "serviceAccount" and principal:
                members.append(("service_account", principal))
    return members
