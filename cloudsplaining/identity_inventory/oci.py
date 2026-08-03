"""OCI (Oracle Cloud) identity lifecycle inventory.

Input is the OCI collector snapshot (``users``, ``dynamicGroups``). Users may be
classic IAM users (``oci iam user list`` — kebab-case keys) or Identity Domains
users (SCIM shape with ``meta.created`` / ``idcsCreatedBy``); both are
understood. Optional enrichment key:

- ``auditEvents``: OCI Audit events (CloudEvents envelope or simplified dicts)
  — fills ``created_by`` for identities lacking ``idcsCreatedBy``.

Dynamic groups are OCI's workload identities and are always machines. Users with
API keys but no console password are service accounts by convention → machine.
"""

# Copyright (c) 2020, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
from __future__ import annotations

from typing import Any

from cloudsplaining.identity_inventory.classify import machine_name_signal, resolve
from cloudsplaining.identity_inventory.model import HUMAN, MACHINE, IdentityRecord
from cloudsplaining.identity_inventory.parsing import as_bool, get_field, parse_timestamp

PROVIDER = "oci"

USER_STATE_EXTENSION = "urn:ietf:params:scim:schemas:oracle:idcs:extension:userState:User"
USER_CAPABILITIES_EXTENSION = "urn:ietf:params:scim:schemas:oracle:idcs:extension:capabilities:User"

#: Shared with the OCI collector, which pre-filters audit events to these kinds.
CREATION_EVENT_SUFFIXES = ("createuser", "createdynamicgroup")


def build_inventory(data: dict[str, Any]) -> list[IdentityRecord]:
    """Inventory users and dynamic groups (plain groups are memberships, not identities)."""
    creators = _audit_creators(data.get("auditEvents") or [])
    records = [_user_record(user, creators) for user in data.get("users") or []]
    records += [_dynamic_group_record(group, creators) for group in data.get("dynamicGroups") or []]
    return records


def _user_record(user: dict[str, Any], creators: dict[str, str]) -> IdentityRecord:
    name = get_field(user, "name") or get_field(user, "userName") or ""
    meta = user.get("meta") or {}
    state = user.get(USER_STATE_EXTENSION) or {}
    last_login = get_field(user, "lastSuccessfulLoginTime", "lastSuccessfulLoginDate") or get_field(
        state, "lastSuccessfulLoginDate"
    )
    classification, reason = _user_classification(user, name, last_login)
    return IdentityRecord(
        provider=PROVIDER,
        identity_type="user",
        id=user.get("id") or name,
        name=name,
        classification=classification,
        classification_reason=reason,
        created_at=parse_timestamp(get_field(user, "timeCreated") or get_field(meta, "created")),
        last_used=parse_timestamp(last_login),
        created_by=_idcs_creator(user) or creators.get(name),
    )


def _user_classification(user: dict[str, Any], name: str, last_login: object) -> tuple[str, str]:
    """Machine-name → MFA → API-key-only shape → login history → console default → unknown.

    Current capability state outranks historical logins: an account converted to a
    service user (console disabled, keys added) keeps its old login timestamp, but
    what it is *now* is a machine. MFA ranks higher because enrollment is current state.
    """
    capabilities = _capabilities(user)
    console = get_field(capabilities, "canUseConsolePassword")
    api_keys = get_field(capabilities, "canUseApiKeys")
    # MFA enrollment is a human act — it exists only for console logins.
    mfa = (HUMAN, "MFA enrolled") if as_bool(get_field(user, "isMfaActivated")) else None
    api_key_only = (MACHINE, "API-key-only capabilities") if console is False and as_bool(api_keys) else None
    login = (HUMAN, "console login recorded") if parse_timestamp(last_login) is not None else None
    # Console capability is the creation default, so this is weak evidence;
    # the reason string flags it.
    console_capable = (HUMAN, "console-capable (default)") if as_bool(console) else None
    return resolve(
        machine_name_signal(name),
        mfa,
        api_key_only,
        login,
        console_capable,
        fallback="no capability or activity evidence",
    )


def _capabilities(user: dict[str, Any]) -> dict[str, Any]:
    """Capability flags from the classic key merged over the Identity Domains SCIM extension."""
    return {**(user.get(USER_CAPABILITIES_EXTENSION) or {}), **(user.get("capabilities") or {})}


def _idcs_creator(user: dict[str, Any]) -> str | None:
    created_by = get_field(user, "idcsCreatedBy")
    if not isinstance(created_by, dict):
        return None
    return get_field(created_by, "display") or get_field(created_by, "value")


def _dynamic_group_record(group: dict[str, Any], creators: dict[str, str]) -> IdentityRecord:
    name = get_field(group, "name") or ""
    return IdentityRecord(
        provider=PROVIDER,
        identity_type="dynamic_group",
        id=group.get("id") or name,
        name=name,
        classification=MACHINE,
        classification_reason="workload identity",
        created_at=parse_timestamp(get_field(group, "timeCreated")),
        created_by=creators.get(name),
    )


def _audit_creators(events: list[dict[str, Any]]) -> dict[str, str]:
    """Map created resource name -> creator principal from identity-creation audit events."""
    creators: dict[str, str] = {}
    for event in events:
        kind = str(get_field(event, "eventType") or get_field(event, "eventName") or "").lower()
        if not kind.endswith(CREATION_EVENT_SUFFIXES):
            continue
        payload = event.get("data") or {}
        identity = get_field(payload, "identity") or {}
        target = get_field(payload, "resourceName") or get_field(event, "resourceName")
        actor = get_field(identity, "principalName") or get_field(event, "principalName")
        if target and actor:
            creators[target] = actor
    return creators
