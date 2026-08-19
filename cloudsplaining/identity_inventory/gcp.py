"""GCP identity lifecycle inventory.

Input is the GCP collector snapshot (``serviceAccounts``, ``bindings``) plus,
optionally:

- ``users``: a Workspace / Cloud Identity directory export
  (Admin SDK ``users.list``) — human users with ``creationTime`` /
  ``lastLoginTime``.
- ``auditLogEntries``: Admin Activity log entries — fills service-account
  ``created_at`` / ``created_by`` from ``CreateServiceAccount`` calls, human
  users' ``last_used`` from their latest logged activity, and human users'
  ``created_at`` / ``created_by`` from the ``SetIamPolicy`` grant that first
  added them (the in-GCP proxy that replaces the Workspace Admin SDK scope).
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

from cloudsplaining.identity_inventory.classify import machine_name_signal
from cloudsplaining.identity_inventory.model import HUMAN, MACHINE, IdentityRecord
from cloudsplaining.identity_inventory.parsing import get_field, max_timestamp, parse_timestamp

PROVIDER = "gcp"

#: Workspace exports report "never logged in" as the Unix epoch.
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def build_inventory(data: dict[str, Any]) -> list[IdentityRecord]:
    """Inventory service accounts and human users; groups/domains are not identities."""
    audit_entries = data.get("auditLogEntries") or []
    sa_audit = _sa_audit(audit_entries)
    activities = _sa_activities(data.get("serviceAccountActivities") or [])
    user_activity = _user_activity(audit_entries)
    user_grants = _user_grants(audit_entries)

    records: list[IdentityRecord] = []
    seen: set[str] = set()
    for sa in data.get("serviceAccounts") or []:
        email = get_field(sa, "email") or ""
        records.append(_sa_record(sa, sa_audit, activities))
        seen.add(email)
    for user in data.get("users") or []:
        email = get_field(user, "primaryEmail") or ""
        records.append(_user_record(user, user_activity, user_grants))
        seen.add(email)
    for member_type, email in _binding_members(data.get("bindings") or []):
        if email in seen:
            continue
        seen.add(email)
        if member_type == "service_account":
            records.append(_sa_record({"email": email}, sa_audit, activities))
        else:
            records.append(_member_user_record(email, user_activity, user_grants))
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
        classification_reason="service account",
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
def _user_record(
    user: dict[str, Any],
    user_activity: dict[str, datetime],
    user_grants: dict[str, tuple[datetime, str | None]],
) -> IdentityRecord:
    email = get_field(user, "primaryEmail") or ""
    last_login = parse_timestamp(get_field(user, "lastLoginTime"))
    if last_login == _EPOCH:
        last_login = None
    grant_time, grant_actor = user_grants.get(email, (None, None))
    classification, reason = machine_name_signal(email) or (HUMAN, "Workspace directory user")
    return IdentityRecord(
        provider=PROVIDER,
        identity_type="user",
        id=user.get("id") or email,
        name=email,
        classification=classification,
        classification_reason=reason,
        # The Workspace directory creationTime is authoritative; the first
        # SetIamPolicy grant is only a proxy for when the user entered GCP.
        created_at=parse_timestamp(get_field(user, "creationTime")) or grant_time,
        last_used=max_timestamp(last_login, user_activity.get(email)),
        created_by=grant_actor,
    )


def _member_user_record(
    email: str,
    user_activity: dict[str, datetime],
    user_grants: dict[str, tuple[datetime, str | None]],
) -> IdentityRecord:
    grant_time, grant_actor = user_grants.get(email, (None, None))
    classification, reason = machine_name_signal(email) or (HUMAN, "user: IAM binding member")
    return IdentityRecord(
        provider=PROVIDER,
        identity_type="user",
        id=email,
        name=email,
        classification=classification,
        classification_reason=reason,
        created_at=grant_time,
        last_used=user_activity.get(email),
        created_by=grant_actor,
    )


def _user_activity(entries: list[dict[str, Any]]) -> dict[str, datetime]:
    """Map principal email -> latest audit-log activity timestamp."""
    latest: dict[str, datetime] = {}
    for entry in entries:
        payload = get_field(entry, "protoPayload") or {}
        email = get_field(get_field(payload, "authenticationInfo") or {}, "principalEmail")
        stamp = parse_timestamp(get_field(entry, "timestamp") or get_field(entry, "receiveTimestamp"))
        if not email or stamp is None:
            continue
        if email not in latest or stamp > latest[email]:
            latest[email] = stamp
    return latest


def _user_grants(entries: list[dict[str, Any]]) -> dict[str, tuple[datetime, str | None]]:
    """Map user email -> (earliest SetIamPolicy ADD timestamp, granting principal).

    The grant that first added a ``user:`` member is the closest in-GCP proxy for
    created_at/created_by without the Workspace Admin SDK scope.
    """
    grants: dict[str, tuple[datetime, str | None]] = {}
    for entry in entries:
        payload = get_field(entry, "protoPayload") or {}
        method = get_field(payload, "methodName") or ""
        if not method.endswith("SetIamPolicy"):
            continue
        stamp = parse_timestamp(get_field(entry, "timestamp") or get_field(entry, "receiveTimestamp"))
        if stamp is None:
            continue
        actor = get_field(get_field(payload, "authenticationInfo") or {}, "principalEmail")
        delta = get_field(get_field(payload, "serviceData") or {}, "policyDelta") or {}
        for binding_delta in get_field(delta, "bindingDeltas") or []:
            if str(get_field(binding_delta, "action") or "").upper() != "ADD":
                continue
            kind, _, member_email = str(get_field(binding_delta, "member") or "").partition(":")
            if kind != "user" or not member_email:
                continue
            if member_email not in grants or stamp < grants[member_email][0]:
                grants[member_email] = (stamp, actor)
    return grants


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
