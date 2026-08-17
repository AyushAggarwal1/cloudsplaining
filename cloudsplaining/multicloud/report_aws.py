"""Serialize an :class:`AccountModel` into the AWS report JSON shape.

The output mirrors ``iam-findings-default.json``: top-level ``account_id`` and
``provider`` first, then ``users``, ``groups``, ``roles``,
``aws_managed_policies``, ``customer_managed_policies``, ``inline_policies``,
``exclusions``, and ``links``. Identity entries reference
their attached policies via ``{policy_id: policy_name}`` dicts; policy entries
carry the per-category findings and an ``AttachedTo`` back-reference.
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
    CUSTOMER,
    GROUP,
    INLINE,
    MANAGED,
    ROLE,
    USER,
    AccountModel,
    Policy,
    Principal,
)
from cloudsplaining.shared.exclusions import DEFAULT_EXCLUSIONS, Exclusions


def managed_policies_key(provider: str) -> str:
    """The provider-managed policy collection key, e.g. ``azure_managed_policies``.

    The AWS report calls this ``aws_managed_policies``; for other clouds we use
    the provider's own name so the key isn't misleading.
    """
    return f"{provider}_managed_policies"


def policy_collection_keys(report: dict[str, Any]) -> list[str]:
    """Return the policy collection keys present in ``report`` (provider-agnostic)."""
    keys = [k for k in report if k.endswith("_managed_policies")]
    if "inline_policies" in report:
        keys.append("inline_policies")
    return keys


def render(model: AccountModel, exclusions: Exclusions = DEFAULT_EXCLUSIONS) -> dict[str, Any]:
    """Return the full AWS-shaped report dict for ``model``."""
    report: dict[str, Any] = {
        "account_id": model.account_id,
        "provider": model.provider,
        "groups": {pid: _principal_entry(p, model.provider, exclusions) for pid, p in model.groups.items()},
        "users": {pid: _principal_entry(p, model.provider, exclusions) for pid, p in model.users.items()},
        "roles": {pid: _principal_entry(p, model.provider, exclusions) for pid, p in model.roles.items()},
        managed_policies_key(model.provider): _policy_collection(model, MANAGED, exclusions),
        "customer_managed_policies": _policy_collection(model, CUSTOMER, exclusions),
        "inline_policies": _policy_collection(model, INLINE, exclusions),
        "exclusions": exclusions.config,
        "links": {},
    }
    return report


def _principal_entry(principal: Principal, provider: str, exclusions: Exclusions) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "id": principal.id,
        "name": principal.name,
        "provider_kind": principal.kind,
        "inline_policies": dict(principal.inline_policies),
        "customer_managed_policies": dict(principal.customer_managed_policies),
        managed_policies_key(provider): dict(principal.managed_policies),
        "is_excluded": _is_excluded(principal.name, principal.kind, exclusions),
    }
    # Carry through provider-specific metadata (arn-like id, scopes, create_date, ...).
    entry.update(principal.metadata)
    if principal.kind == USER:
        entry["groups"] = list(principal.groups)
    return entry


def _policy_collection(model: AccountModel, kind: str, exclusions: Exclusions) -> dict[str, Any]:
    return {pid: _policy_entry(p, exclusions) for pid, p in model.policies.items() if p.kind == kind}


def _policy_entry(policy: Policy, exclusions: Exclusions) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "PolicyName": policy.name,
        "PolicyId": policy.id,
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
    if kind == ROLE:
        return exclusions.is_principal_excluded(name, "Role")
    return exclusions.is_policy_excluded(name)
