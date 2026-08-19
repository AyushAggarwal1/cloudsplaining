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

from typing import Any

from cloudsplaining.identity_inventory.classify import machine_name_signal, resolve
from cloudsplaining.identity_inventory.model import HUMAN, MACHINE, UNKNOWN, IdentityRecord
from cloudsplaining.identity_inventory.parsing import get_field, max_timestamp, parse_timestamp

PROVIDER = "azure"

_CREATION_ACTIVITIES = ("Add user", "Add service principal", "Invite external user")

_SYNC_UPN_PREFIX = "sync_"
_SYNC_DISPLAY_NAME = "on-premises directory synchronization service account"


def build_inventory(data: dict[str, Any]) -> list[IdentityRecord]:
    """Inventory every user and service principal (groups are memberships, not identities)."""
    creators = _audit_creators(data.get("directoryAudits") or [])
    sp_sign_ins = _sp_sign_ins(data.get("servicePrincipalSignInActivities") or [])
    users = data.get("users") or []
    sign_in_available = _sign_in_available(users)
    records = [_user_record(user, creators, sign_in_available) for user in users]
    records += [_sp_record(sp, creators, sp_sign_ins) for sp in data.get("servicePrincipals") or []]
    return records


def _sign_in_available(users: list[dict[str, Any]]) -> bool:
    """Whether the snapshot carries sign-in activity at all (needs AuditLog.Read.All + Entra P1)."""
    return any(get_field(user, "signInActivity") for user in users)


def _user_record(user: dict[str, Any], creators: dict[str, str], sign_in_available: bool) -> IdentityRecord:
    name = get_field(user, "userPrincipalName") or get_field(user, "displayName") or ""
    sign_in = get_field(user, "signInActivity") or {}
    classification, reason = _user_classification(user, sign_in_available)
    return IdentityRecord(
        provider=PROVIDER,
        identity_type="user",
        id=user.get("id") or name,
        name=name,
        classification=classification,
        classification_reason=reason,
        created_at=parse_timestamp(get_field(user, "createdDateTime")),
        last_used=max_timestamp(
            get_field(sign_in, "lastSignInDateTime"),
            get_field(sign_in, "lastNonInteractiveSignInDateTime"),
            get_field(sign_in, "lastSuccessfulSignInDateTime"),
        ),
        created_by=_creator_for(user, creators),
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


def _sp_record(sp: dict[str, Any], creators: dict[str, str], sp_sign_ins: dict[str, Any]) -> IdentityRecord:
    name = get_field(sp, "displayName") or get_field(sp, "appId") or ""
    sign_in = get_field(sp, "signInActivity") or {}
    return IdentityRecord(
        provider=PROVIDER,
        identity_type="service_principal",
        id=sp.get("id") or name,
        name=name,
        # Applications, managed identities, and legacy SPs are all workloads.
        classification=MACHINE,
        classification_reason="service principal",
        created_at=parse_timestamp(get_field(sp, "createdDateTime")),
        last_used=max_timestamp(
            get_field(sign_in, "lastSignInDateTime"),
            sp_sign_ins.get(get_field(sp, "appId") or ""),
        ),
        created_by=_creator_for(sp, creators),
    )


def _sp_sign_ins(activities: list[dict[str, Any]]) -> dict[str, Any]:
    """Map appId -> last sign-in timestamp value from the Entra SP sign-in report."""
    sign_ins: dict[str, Any] = {}
    for activity in activities:
        app_id = get_field(activity, "appId")
        last = get_field(activity, "lastSignInActivity") or {}
        if app_id:
            sign_ins[app_id] = get_field(last, "lastSignInDateTime") or get_field(activity, "lastSignInDateTime")
    return sign_ins


def _audit_creators(audits: list[dict[str, Any]]) -> dict[str, str]:
    """Map target id/UPN/displayName -> initiator for identity-creation audit entries."""
    creators: dict[str, str] = {}
    for entry in audits:
        if get_field(entry, "activityDisplayName") not in _CREATION_ACTIVITIES:
            continue
        initiated = get_field(entry, "initiatedBy") or {}
        actor = get_field(initiated.get("user") or {}, "userPrincipalName") or get_field(
            initiated.get("app") or {}, "displayName"
        )
        if not actor:
            continue
        for target in get_field(entry, "targetResources") or []:
            for key in (target.get("id"), get_field(target, "userPrincipalName"), get_field(target, "displayName")):
                if key:
                    creators[key] = actor
    return creators


def _creator_for(identity: dict[str, Any], creators: dict[str, str]) -> str | None:
    for key in (identity.get("id"), get_field(identity, "userPrincipalName"), get_field(identity, "displayName")):
        if key and key in creators:
            return creators[key]
    return None
