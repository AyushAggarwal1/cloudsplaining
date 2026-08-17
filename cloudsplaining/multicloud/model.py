"""In-memory model of a cloud account's IAM, mirroring the AWS report graph.

The AWS report is an identity + policy graph: ``users`` / ``groups`` / ``roles``
reference the policies attached to them, while the policy collections
(``aws_managed_policies`` / ``customer_managed_policies`` / ``inline_policies``)
carry the actual risk findings. This module provides cloud-agnostic dataclasses
that each provider engine populates, after which
:mod:`cloudsplaining.multicloud.report_aws` serializes them into the exact same
JSON shape AWS produces.
"""

# Copyright (c) 2020, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Principal "kinds" map onto the three AWS identity collections.
USER = "user"
GROUP = "group"
ROLE = "role"  # workload identities: Azure SP/MI, GCP service account, OCI dynamic-group

# Policy "kinds" map onto the three AWS policy collections.
MANAGED = "managed"  # provider-managed (Azure built-in roles, GCP predefined roles)
CUSTOMER = "customer"  # customer-authored (custom roles, OCI policies)
INLINE = "inline"  # embedded in a single principal


@dataclass
class Policy:
    """A permission set that carries risk findings, attachable to principals."""

    id: str
    name: str
    kind: str  # MANAGED | CUSTOMER | INLINE
    #: category -> {"severity": str, "description": str, "findings": list}
    categories: dict[str, dict[str, Any]] = field(default_factory=dict)
    #: back-references, populated as principals attach: {"users": [...], "groups": [...], "roles": [...]}
    attached_to: dict[str, list[str]] = field(default_factory=lambda: {"users": [], "groups": [], "roles": []})
    metadata: dict[str, Any] = field(default_factory=dict)
    #: the principal this inline policy belongs to (INLINE only)
    parent: str | None = None

    @property
    def attachment_count(self) -> int:
        return sum(len(v) for v in self.attached_to.values())

    def has_findings(self) -> bool:
        return any(block.get("findings") for block in self.categories.values())


@dataclass
class Principal:
    """A user, group, or workload identity (role)."""

    id: str
    name: str
    kind: str  # USER | GROUP | ROLE
    metadata: dict[str, Any] = field(default_factory=dict)
    #: policy-id -> policy-name, split by policy kind (mirrors the AWS entry layout)
    customer_managed_policies: dict[str, str] = field(default_factory=dict)
    managed_policies: dict[str, str] = field(default_factory=dict)
    inline_policies: dict[str, str] = field(default_factory=dict)
    #: group names this principal belongs to (users -> groups), like AWS user.groups
    groups: list[str] = field(default_factory=list)


class AccountModel:
    """Holds every principal and policy discovered for one account/provider."""

    def __init__(self, provider: str, account_id: str = "") -> None:
        self.provider = provider
        #: subscription/project/tenancy the snapshot was collected from ("" if unknown)
        self.account_id = account_id
        self.users: dict[str, Principal] = {}
        self.groups: dict[str, Principal] = {}
        self.roles: dict[str, Principal] = {}
        # All policies live in one index keyed by id; `kind` decides the output collection.
        self.policies: dict[str, Policy] = {}

    # ----------------------------------------------------------- registration
    def add_principal(self, principal: Principal) -> Principal:
        """Add (or return the existing) principal of the given kind."""
        bucket = self._bucket(principal.kind)
        existing = bucket.get(principal.id)
        if existing is not None:
            return existing
        bucket[principal.id] = principal
        return principal

    def add_policy(self, policy: Policy) -> Policy:
        existing = self.policies.get(policy.id)
        if existing is not None:
            return existing
        self.policies[policy.id] = policy
        return policy

    def get_principal(self, kind: str, principal_id: str) -> Principal | None:
        return self._bucket(kind).get(principal_id)

    # -------------------------------------------------------------- attaching
    def attach(self, principal: Principal, policy: Policy) -> None:
        """Record that ``principal`` holds ``policy`` (both directions)."""
        if policy.kind == MANAGED:
            principal.managed_policies[policy.id] = policy.name
        elif policy.kind == INLINE:
            principal.inline_policies[policy.id] = policy.name
        else:
            principal.customer_managed_policies[policy.id] = policy.name

        collection = {USER: "users", GROUP: "groups", ROLE: "roles"}[principal.kind]
        if principal.name not in policy.attached_to[collection]:
            policy.attached_to[collection].append(principal.name)

    # --------------------------------------------------------------- helpers
    def _bucket(self, kind: str) -> dict[str, Principal]:
        return {USER: self.users, GROUP: self.groups, ROLE: self.roles}[kind]

    def policies_of_kind(self, kind: str) -> dict[str, Policy]:
        return {pid: p for pid, p in self.policies.items() if p.kind == kind}
