"""In-memory model of a cloud account's IAM, serialized with provider-native keys.

Each provider engine populates this identity + permission-set graph: ``users``
and ``groups`` reference the permission sets attached to them, while the
permission sets (Azure/GCP role definitions, OCI policies) carry the actual
risk findings. :mod:`cloudsplaining.multicloud.serialize` turns the model into
the report dict, naming the permission-set collection after the provider's own
vocabulary (``roles`` for Azure/GCP, ``policies`` for OCI).

Workload identities are not a separate collection: Azure service principals
and GCP service accounts are users, and OCI dynamic groups are groups, each
discriminated by ``provider_kind`` metadata.
"""

# Copyright (c) 2020, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Principal kinds. Workload identities (service principals, service accounts,
# dynamic groups) are USER or GROUP principals with a ``provider_kind``
# metadata discriminator.
USER = "user"
GROUP = "group"


@dataclass
class Policy:
    """A permission set that carries risk findings, attachable to principals.

    "Policy" is the internal name; providers serialize these as role
    definitions (Azure), roles (GCP), or policies (OCI). The provider-native
    type (``roleType`` / ``policyType``) lives in ``metadata``.
    """

    id: str
    name: str
    #: category -> {"severity": str, "description": str, "findings": list}
    categories: dict[str, dict[str, Any]] = field(default_factory=dict)
    #: back-references, populated as principals attach: {"users": [...], "groups": [...]}
    attached_to: dict[str, list[str]] = field(default_factory=lambda: {"users": [], "groups": []})
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def attachment_count(self) -> int:
        return sum(len(v) for v in self.attached_to.values())

    def has_findings(self) -> bool:
        return any(block.get("findings") for block in self.categories.values())


@dataclass
class Principal:
    """A user or group, including workload identities (see ``provider_kind``)."""

    id: str
    name: str
    kind: str  # USER | GROUP
    metadata: dict[str, Any] = field(default_factory=dict)
    #: permission-set id -> name; serialized as ``roles`` or ``policies`` per provider
    permission_sets: dict[str, str] = field(default_factory=dict)
    #: group names this principal belongs to (users -> groups), like AWS user.groups
    groups: list[str] = field(default_factory=list)


class AccountModel:
    """Holds every principal and permission set discovered for one account/provider."""

    def __init__(self, provider: str, account_id: str = "") -> None:
        self.provider = provider
        #: subscription/project/tenancy the snapshot was collected from ("" if unknown)
        self.account_id = account_id
        self.users: dict[str, Principal] = {}
        self.groups: dict[str, Principal] = {}
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
        principal.permission_sets[policy.id] = policy.name
        collection = {USER: "users", GROUP: "groups"}[principal.kind]
        if principal.name not in policy.attached_to[collection]:
            policy.attached_to[collection].append(principal.name)

    # --------------------------------------------------------------- helpers
    def _bucket(self, kind: str) -> dict[str, Principal]:
        return {USER: self.users, GROUP: self.groups}[kind]
