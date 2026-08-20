"""Azure RBAC engine: build an :class:`AccountModel` from an Azure IAM snapshot.

Snapshot schema (all keys optional; parsed JSON)::

    {
      "users":               [ <Graph user> ],
      "groups":              [ <Graph group> ],
      "servicePrincipals":   [ <Graph servicePrincipal / managed identity> ],
      "roleDefinitions":     [ <role definition> ],   # built-in + custom
      "roleAssignments":     [ <role assignment> ],
      "groupMemberships":    { "<groupId>": ["<memberId>", ...] }
    }

Backward compatibility: a bare list (or ``{"roleDefinitions": [...]}``) is treated
as role definitions only, with empty identity collections.

Role definitions (built-in and custom) become the report's ``roles``
collection, each entry carrying its ``roleType``. Service principals and
managed identities are users with ``provider_kind: "service_principal"``.
"""

# Copyright (c) 2020, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
from __future__ import annotations

from typing import Any

from cloudsplaining.multicloud.analysis import analyze_azure_role
from cloudsplaining.multicloud.model import (
    GROUP,
    USER,
    AccountModel,
    Policy,
    Principal,
)
from cloudsplaining.multicloud.provider import Provider

# principalType (from role assignments / Graph) -> (kind, provider_kind)
_PRINCIPAL_KIND = {
    "user": (USER, "user"),
    "group": (GROUP, "group"),
    "serviceprincipal": (USER, "service_principal"),
    "managedidentity": (USER, "service_principal"),
    "msi": (USER, "service_principal"),
    "foreigngroup": (GROUP, "group"),
}


def _expand_permissions(role: dict[str, Any]) -> tuple[list[str], list[str]]:
    actions: list[str] = []
    data_actions: list[str] = []
    for block in role.get("permissions", []) or []:
        actions.extend(block.get("actions", []) or [])
        data_actions.extend(block.get("dataActions", []) or [])
    return actions, data_actions


def _not_actions(role: dict[str, Any]) -> set[str]:
    excluded: set[str] = set()
    for block in role.get("permissions", []) or []:
        for na in block.get("notActions", []) or []:
            excluded.add(na.strip().lower())
    return excluded


class AzureProvider(Provider):
    name = "azure"

    def scan(self, data: Any) -> AccountModel:
        snapshot = self._normalize(data)
        model = AccountModel(self.name, account_id=str(snapshot.get("account_id") or ""))

        self._add_identities(snapshot, model)
        role_def_index = self._add_role_definitions(snapshot, model)
        self._add_memberships(snapshot, model)
        self._apply_assignments(snapshot, model, role_def_index)

        return model

    # ------------------------------------------------------------------ input
    @staticmethod
    def _normalize(data: Any) -> dict[str, Any]:
        if isinstance(data, list):
            return {"roleDefinitions": data}
        if isinstance(data, dict):
            if "roleDefinitionList" in data and "roleDefinitions" not in data:
                data = {**data, "roleDefinitions": data["roleDefinitionList"]}
            if "roleAssignmentList" in data and "roleAssignments" not in data:
                data = {**data, "roleAssignments": data["roleAssignmentList"]}
            return data
        raise ValueError("Azure input must be a list of role definitions or a snapshot object.")

    # ------------------------------------------------------------- identities
    def _add_identities(self, snapshot: dict[str, Any], model: AccountModel) -> None:
        for user in snapshot.get("users", []) or []:
            pid = user.get("id") or user.get("objectId") or user.get("userPrincipalName")
            name = user.get("userPrincipalName") or user.get("displayName") or pid
            model.add_principal(
                Principal(
                    id=str(pid),
                    name=str(name),
                    kind=USER,
                    metadata={"displayName": user.get("displayName"), "accountEnabled": user.get("accountEnabled")},
                )
            )
        for group in snapshot.get("groups", []) or []:
            pid = group.get("id") or group.get("objectId")
            name = group.get("displayName") or pid
            model.add_principal(Principal(id=str(pid), name=str(name), kind=GROUP))
        for sp in snapshot.get("servicePrincipals", []) or []:
            pid = sp.get("id") or sp.get("objectId") or sp.get("appId")
            name = sp.get("displayName") or sp.get("appDisplayName") or pid
            model.add_principal(
                Principal(
                    id=str(pid),
                    name=str(name),
                    kind=USER,
                    metadata={
                        "provider_kind": "service_principal",
                        "servicePrincipalType": sp.get("servicePrincipalType"),
                    },
                )
            )

    def _add_role_definitions(self, snapshot: dict[str, Any], model: AccountModel) -> dict[str, Policy]:
        index: dict[str, Policy] = {}
        for role in snapshot.get("roleDefinitions", []) or []:
            role_name = role.get("roleName") or role.get("name") or role.get("id") or "<unknown role>"
            role_id = role.get("id") or role.get("name") or role_name

            actions, data_actions = _expand_permissions(role)
            scopes = role.get("assignableScopes", []) or []
            categories = analyze_azure_role(actions, data_actions, _not_actions(role), scopes)

            policy = Policy(
                id=str(role_id),
                name=str(role_name),
                categories=categories.result(),
                metadata={
                    "roleType": role.get("roleType") or role.get("type") or "BuiltInRole",
                    "assignableScopes": scopes,
                    "Path": "/",
                    # Full set of permissions the role grants (not just the risky ones).
                    "Actions": list(actions),
                    "DataActions": list(data_actions),
                    "NotActions": sorted(_not_actions(role)),
                    "PolicyVersionList": [
                        {
                            "Document": {"permissions": role.get("permissions", []) or []},
                            "VersionId": "v1",
                            "IsDefaultVersion": True,
                        }
                    ],
                },
            )
            model.add_policy(policy)
            # Index by both id and name so assignments can resolve either form.
            index[str(role_id)] = policy
            index[str(role_name)] = policy
        return index

    def _add_memberships(self, snapshot: dict[str, Any], model: AccountModel) -> None:
        memberships = snapshot.get("groupMemberships", {}) or {}
        for group_id, member_ids in memberships.items():
            group = model.get_principal(GROUP, str(group_id))
            if group is None:
                continue
            for member_id in member_ids:
                user = model.get_principal(USER, str(member_id))
                if user is not None and group.name not in user.groups:
                    user.groups.append(group.name)

    def _apply_assignments(
        self, snapshot: dict[str, Any], model: AccountModel, role_def_index: dict[str, Policy]
    ) -> None:
        for assignment in snapshot.get("roleAssignments", []) or []:
            role_ref = (
                assignment.get("roleDefinitionId") or assignment.get("roleDefinitionName") or assignment.get("roleName")
            )
            policy = self._resolve_policy(role_ref, role_def_index)
            if policy is None:
                continue

            kinds = _PRINCIPAL_KIND.get((assignment.get("principalType") or "").lower())
            principal_id = assignment.get("principalId") or assignment.get("principalName")
            principal_name = assignment.get("principalName") or assignment.get("principalId")
            if principal_id is None:
                continue

            principal = self._resolve_principal(model, kinds, str(principal_id), str(principal_name))
            model.attach(principal, policy)

    # --------------------------------------------------------------- resolving
    @staticmethod
    def _resolve_policy(role_ref: Any, index: dict[str, Policy]) -> Policy | None:
        if role_ref is None:
            return None
        ref = str(role_ref)
        if ref in index:
            return index[ref]
        # role assignment may reference the full ARM id ending in the GUID.
        tail = ref.rsplit("/", 1)[-1]
        if tail in index:
            return index[tail]
        return None

    @staticmethod
    def _resolve_principal(
        model: AccountModel, kinds: tuple[str, str] | None, principal_id: str, principal_name: str
    ) -> Principal:
        # If we know the kind, look it up; otherwise search all buckets.
        if kinds is not None:
            kind, provider_kind = kinds
            existing = model.get_principal(kind, principal_id)
            if existing is not None:
                return existing
            # Assignment references an identity we didn't enumerate: synthesize it.
            metadata = {} if provider_kind == kind else {"provider_kind": provider_kind}
            return model.add_principal(Principal(id=principal_id, name=principal_name, kind=kind, metadata=metadata))
        for k in (USER, GROUP):
            existing = model.get_principal(k, principal_id)
            if existing is not None:
                return existing
        # Unknown type and unknown id -> assume a workload identity.
        return model.add_principal(
            Principal(
                id=principal_id,
                name=principal_name,
                kind=USER,
                metadata={"provider_kind": "service_principal"},
            )
        )
