"""Serialize an :class:`AccountModel` into the provider-native report JSON.

Top-level ``account_id`` and ``provider`` first, then the identity collections
(``users``, ``groups``), the provider's permission-set collection (``roles``
for Azure/GCP, ``policies`` for OCI), ``exclusions``, and ``links``. Identity
entries reference their attached permission sets via a ``{id: name}`` dict
named after the collection; permission-set entries carry the per-category
findings and an ``AttachedTo`` back-reference.
"""

# Copyright (c) 2020, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
from __future__ import annotations

from typing import Any

from cloudsplaining.multicloud.analysis import CATEGORY_ORDER
from cloudsplaining.multicloud.model import (
    GROUP,
    USER,
    AccountModel,
    Policy,
    Principal,
)
from cloudsplaining.shared.exclusions import DEFAULT_EXCLUSIONS, Exclusions

#: provider -> name of the permission-set collection, matching that cloud's
#: own vocabulary (Azure role definitions and GCP roles are "roles"; OCI has
#: no roles concept, its permission sets are "policies").
_PERMISSION_COLLECTION = {
    "azure": "roles",
    "gcp": "roles",
    "oci": "policies",
}

#: Permission-set collections use RoleName/RoleId or PolicyName/PolicyId to
#: match the collection name.
_NAME_FIELDS = {
    "roles": ("RoleName", "RoleId"),
    "policies": ("PolicyName", "PolicyId"),
}


def permission_collection_key(provider: str) -> str:
    """The permission-set collection key for ``provider`` (``roles`` or ``policies``)."""
    return _PERMISSION_COLLECTION.get(provider.strip().lower(), "policies")


def render(model: AccountModel, exclusions: Exclusions = DEFAULT_EXCLUSIONS) -> dict[str, Any]:
    """Return the full report dict for ``model``."""
    collection_key = permission_collection_key(model.provider)
    report: dict[str, Any] = {
        "account_id": model.account_id,
        "provider": model.provider,
        "groups": {pid: _principal_entry(p, collection_key, exclusions) for pid, p in model.groups.items()},
        "users": {pid: _principal_entry(p, collection_key, exclusions) for pid, p in model.users.items()},
        collection_key: {pid: _policy_entry(p, collection_key, exclusions) for pid, p in model.policies.items()},
        "exclusions": exclusions.config,
        "links": {},
    }
    return report


def _principal_entry(principal: Principal, collection_key: str, exclusions: Exclusions) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "id": principal.id,
        "name": principal.name,
        "provider_kind": principal.kind,
        collection_key: dict(principal.permission_sets),
        "is_excluded": _is_excluded(principal.name, principal.kind, exclusions),
    }
    # Carry through provider-specific metadata; a ``provider_kind`` there
    # (service_principal, service_account, dynamic_group, ...) overrides the
    # plain kind.
    entry.update(principal.metadata)
    if principal.kind == USER:
        entry["groups"] = list(principal.groups)
    return entry


def _policy_entry(policy: Policy, collection_key: str, exclusions: Exclusions) -> dict[str, Any]:
    name_field, id_field = _NAME_FIELDS[collection_key]
    entry: dict[str, Any] = {
        name_field: policy.name,
        id_field: policy.id,
        "AttachmentCount": policy.attachment_count,
        "AttachedTo": dict(policy.attached_to),
    }
    entry.update(policy.metadata)
    for category in CATEGORY_ORDER:
        entry[category] = policy.categories.get(category, {"severity": "none", "description": "", "findings": []})
    entry["is_excluded"] = _is_excluded(policy.name, "policy", exclusions)
    return entry


def _is_excluded(name: str, kind: str, exclusions: Exclusions) -> bool:
    """Mirror the AWS exclusion semantics using the shared Exclusions helper."""
    if kind == USER:
        return exclusions.is_principal_excluded(name, "User")
    if kind == GROUP:
        return exclusions.is_principal_excluded(name, "Group")
    return exclusions.is_policy_excluded(name)
