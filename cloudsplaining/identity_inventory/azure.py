"""Azure (Entra ID) identity lifecycle inventory.

Input is the Microsoft Graph snapshot the Azure collector produces (``users``,
``servicePrincipals``); requesting ``createdDateTime`` and ``signInActivity`` in
the ``$select`` (the latter needs ``AuditLog.Read.All``) fills the lifecycle
fields. Optional enrichment keys on the same dict:

- ``servicePrincipalSignInActivities``: rows of the Entra
  ``reports/servicePrincipalSignInActivities`` API — fills service-principal
  ``last_used`` (matched by ``appId``).
- ``directoryAudits``: directory audit log entries — fills ``created_by`` from
  "Add user" / "Add service principal" / "Invite external user" activities.
"""

# Copyright (c) 2020, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
from __future__ import annotations

from operator import itemgetter
from typing import TYPE_CHECKING, Any

from cloudsplaining.identity_inventory.classify import machine_name_signal, resolve
from cloudsplaining.identity_inventory.model import HUMAN, MACHINE, UNKNOWN, IdentityRecord
from cloudsplaining.identity_inventory.parsing import get_field, max_timestamp, parse_timestamp

if TYPE_CHECKING:
    from datetime import datetime

PROVIDER = "azure"

_CREATION_ACTIVITIES = ("Add user", "Add service principal", "Invite external user")

_SYNC_UPN_PREFIX = "sync_"
_SYNC_DISPLAY_NAME = "on-premises directory synchronization service account"


def build_inventory(data: dict[str, Any]) -> list[IdentityRecord]:
    """Inventory Graph identities plus RBAC-only users/SPs (groups are memberships)."""
    creators = _audit_creators(data.get("directoryAudits") or [])
    sp_sign_ins = _sp_sign_ins(data.get("servicePrincipalSignInActivities") or [])
    users = data.get("users") or []
    sign_in_available = _sign_in_available(users)
    records = [_user_record(user, creators, sign_in_available) for user in users]
    records += [_sp_record(sp, creators, sp_sign_ins) for sp in data.get("servicePrincipals") or []]
    seen_ids = {record.id.lower() for record in records if record.id}
    for assignment in data.get("roleAssignments") or []:
        record = _assignment_only_record(assignment)
        if record is not None and record.id.lower() not in seen_ids:
            records.append(record)
            seen_ids.add(record.id.lower())
    return records


def _sign_in_available(users: list[dict[str, Any]]) -> bool:
    """Whether the snapshot carries sign-in activity at all (needs AuditLog.Read.All + Entra P1)."""
    return any(get_field(user, "signInActivity") for user in users)


def _user_record(
    user: dict[str, Any],
    creators: dict[str, list[tuple[datetime | None, str]]],
    sign_in_available: bool,
) -> IdentityRecord:
    name = get_field(user, "userPrincipalName") or get_field(user, "displayName") or ""
    sign_in = get_field(user, "signInActivity") or {}
    created_at = parse_timestamp(get_field(user, "createdDateTime"))
    classification, reason = _user_classification(user, sign_in_available)
    return IdentityRecord(
        provider=PROVIDER,
        identity_type="user",
        id=user.get("id") or name,
        name=name,
        classification=classification,
        classification_reason=reason,
        created_at=created_at,
        last_used=max_timestamp(
            get_field(sign_in, "lastSignInDateTime"),
            get_field(sign_in, "lastNonInteractiveSignInDateTime"),
            get_field(sign_in, "lastSuccessfulSignInDateTime"),
        ),
        created_by=_creator_for(user, creators, created_at),
    )


def _user_classification(user: dict[str, Any], sign_in_available: bool) -> tuple[str, str]:
    """Sync-account names → machine names → sign-in shape; soft human only without sign-in data."""
    name = get_field(user, "userPrincipalName") or get_field(user, "displayName") or ""
    display_name = get_field(user, "displayName")
    return resolve(
        _sync_account_signal(name, display_name),
        machine_name_signal(name, display_name),
        _sign_in_signal(get_field(user, "signInActivity") or {}, sign_in_available),
        fallback="no sign-in evidence",
    )


def _sync_account_signal(name: str, display_name: str | None) -> tuple[str, str] | None:
    if name.lower().startswith(_SYNC_UPN_PREFIX) or (display_name or "").lower() == _SYNC_DISPLAY_NAME:
        return (MACHINE, "directory synchronization account")
    return None


def _sign_in_signal(sign_in: dict[str, Any], available: bool) -> tuple[str, str] | None:
    """Interactive sign-ins are a human act; only-non-interactive is credential automation."""
    interactive = get_field(sign_in, "lastSignInDateTime") or get_field(sign_in, "lastSuccessfulSignInDateTime")
    if interactive:
        return (HUMAN, "interactive sign-ins")
    if get_field(sign_in, "lastNonInteractiveSignInDateTime"):
        return (MACHINE, "non-interactive sign-ins only")
    if available:
        return (UNKNOWN, "never signed in")
    # An Entra user object is a people-directory entry by construction; without any
    # sign-in data in the tenant the honest best guess stays human — stated, not silent.
    return (HUMAN, "Entra user (sign-in data unavailable)")


def _sp_record(
    sp: dict[str, Any],
    creators: dict[str, list[tuple[datetime | None, str]]],
    sp_sign_ins: dict[str, Any],
) -> IdentityRecord:
    name = get_field(sp, "displayName") or get_field(sp, "appId") or ""
    sign_in = get_field(sp, "signInActivity") or {}
    created_at = parse_timestamp(get_field(sp, "createdDateTime"))
    return IdentityRecord(
        provider=PROVIDER,
        identity_type="service_principal",
        id=sp.get("id") or name,
        name=name,
        # Applications, managed identities, and legacy SPs are all workloads.
        classification=MACHINE,
        classification_reason="service principal",
        created_at=created_at,
        last_used=max_timestamp(
            get_field(sign_in, "lastSignInDateTime"),
            sp_sign_ins.get(get_field(sp, "appId") or ""),
        ),
        created_by=_creator_for(sp, creators, created_at),
    )


def _assignment_only_record(assignment: dict[str, Any]) -> IdentityRecord | None:
    """Preserve principals known to Azure RBAC when Graph identity reads are unavailable."""
    principal_id = get_field(assignment, "principalId")
    principal_type = str(get_field(assignment, "principalType") or "").lower()
    if not principal_id:
        return None
    if principal_type == "user":
        classification = UNKNOWN
        reason = "role-assignment user; Graph profile unavailable"
        identity_type = "user"
    elif principal_type in {"serviceprincipal", "managedidentity"}:
        classification = MACHINE
        reason = "service principal (role assignment only)"
        identity_type = "service_principal"
    else:
        return None
    return IdentityRecord(
        provider=PROVIDER,
        identity_type=identity_type,
        id=str(principal_id),
        name=str(principal_id),
        classification=classification,
        classification_reason=reason,
    )


def _sp_sign_ins(activities: list[dict[str, Any]]) -> dict[str, Any]:
    """Map appId -> last sign-in timestamp value from the Entra SP sign-in report."""
    sign_ins: dict[str, Any] = {}
    for activity in activities:
        app_id = get_field(activity, "appId")
        last = get_field(activity, "lastSignInActivity") or {}
        if app_id:
            candidate = get_field(last, "lastSignInDateTime") or get_field(activity, "lastSignInDateTime")
            newest = max_timestamp(sign_ins.get(app_id), candidate)
            if newest is not None:
                sign_ins[app_id] = newest
    return sign_ins


def _audit_creators(audits: list[dict[str, Any]]) -> dict[str, list[tuple[datetime | None, str]]]:
    """Map target keys to timestamped creation-audit initiators."""
    creators: dict[str, list[tuple[datetime | None, str]]] = {}
    for entry in audits:
        if get_field(entry, "activityDisplayName") not in _CREATION_ACTIVITIES:
            continue
        initiated = get_field(entry, "initiatedBy") or {}
        actor = get_field(initiated.get("user") or {}, "userPrincipalName") or get_field(
            initiated.get("app") or {}, "displayName"
        )
        if not actor:
            continue
        stamp = parse_timestamp(get_field(entry, "activityDateTime"))
        for target in get_field(entry, "targetResources") or []:
            for key in (target.get("id"), get_field(target, "userPrincipalName"), get_field(target, "displayName")):
                if key:
                    creators.setdefault(key, []).append((stamp, actor))
    return creators


def _creator_for(
    identity: dict[str, Any],
    creators: dict[str, list[tuple[datetime | None, str]]],
    created_at: datetime | None,
) -> str | None:
    keys = (identity.get("id"), get_field(identity, "userPrincipalName"), get_field(identity, "displayName"))
    for index, key in enumerate(keys):
        candidates = creators.get(key) if key else None
        if not candidates:
            continue
        timed = [(stamp, actor) for stamp, actor in candidates if stamp is not None]
        if created_at is not None and timed:
            stamp, actor = min(timed, key=lambda item: abs((item[0] - created_at).total_seconds()))
            # Object IDs are unique. Name fallbacks must also be temporally close
            # so a deleted namesake cannot supply the current object's creator.
            if index == 0 or abs((stamp - created_at).total_seconds()) <= 24 * 60 * 60:
                return actor
            return None
        if timed:
            return max(timed, key=itemgetter(0))[1]
        return candidates[0][1]
    return None
