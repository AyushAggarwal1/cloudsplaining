"""GCP IAM engine: build an :class:`AccountModel` from a GCP IAM snapshot.

Snapshot schema (all keys optional; parsed JSON)::

    {
      "serviceAccounts": [ {"email": ..., "uniqueId": ..., "displayName": ...} ],
      "customRoles":     [ {"name": "projects/p/roles/r", "includedPermissions": [...]} ],
      "predefinedRoles": [ {"name": "roles/...", "includedPermissions": [...]} ],
      "bindings":        [ {"role": ..., "members": [...], "resource": ...} ],
      "identities":      {"users": [...], "groups": [...]}
    }

Users and groups not listed under ``identities`` are inferred from binding
members. Backward compatibility: a bare list, ``{"bindings": [...]}``, or a raw
``get-iam-policy`` object (``{"bindings": [...], "etag": ...}``) all work.

GCP roles (basic, predefined, and custom) become the report's ``roles``
collection, each entry carrying its ``roleType``. Service accounts are users
with ``provider_kind: "service_account"``. Public members (``allUsers`` /
``allAuthenticatedUsers``) are recorded on the role's ``AttachedTo.public``
list instead of being synthesized as principals.
"""

# Copyright (c) 2020, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
from __future__ import annotations

from typing import Any

from cloudsplaining.multicloud.analysis import analyze_gcp_role
from cloudsplaining.multicloud.findings import PUBLIC_ACCESS
from cloudsplaining.multicloud.gcp import constants as c
from cloudsplaining.multicloud.model import (
    GROUP,
    USER,
    AccountModel,
    Policy,
    Principal,
)
from cloudsplaining.multicloud.provider import Provider


def _norm(value: str) -> str:
    return value.strip().lower()


def _role_type(role_name: str) -> str:
    """basic (owner/editor/viewer) | predefined (``roles/*``) | custom."""
    if role_name in c.BASIC_ROLES:
        return "basic"
    if role_name.startswith("roles/"):
        return "predefined"
    return "custom"


class GcpProvider(Provider):
    name = "gcp"

    def scan(self, data: Any) -> AccountModel:
        snapshot = self._normalize(data)
        model = AccountModel(self.name, account_id=str(snapshot.get("account_id") or ""))

        self._add_service_accounts(snapshot, model)
        self._add_explicit_identities(snapshot, model)
        role_index = self._add_roles(snapshot, model)
        self._apply_bindings(snapshot, model, role_index)

        return model

    # ------------------------------------------------------------------ input
    @staticmethod
    def _normalize(data: Any) -> dict[str, Any]:
        if isinstance(data, list):
            roles = [i for i in data if "includedPermissions" in i]
            bindings = [i for i in data if "role" in i]
            return {"customRoles": roles, "bindings": bindings}
        if isinstance(data, dict):
            snapshot = dict(data)
            if "bindings" not in snapshot:
                if snapshot.get("iamPolicy"):
                    snapshot["bindings"] = snapshot["iamPolicy"].get("bindings", [])
                elif snapshot.get("policy"):
                    snapshot["bindings"] = snapshot["policy"].get("bindings", [])
            return snapshot
        raise ValueError("GCP input must be a list or a snapshot object.")

    # ------------------------------------------------------------- identities
    def _add_service_accounts(self, snapshot: dict[str, Any], model: AccountModel) -> None:
        for sa in snapshot.get("serviceAccounts", []) or []:
            email = sa.get("email") or sa.get("name")
            if not email:
                continue
            member = f"serviceAccount:{email}"
            model.add_principal(
                Principal(
                    id=member,
                    name=email,
                    kind=USER,
                    metadata={
                        "provider_kind": "service_account",
                        "uniqueId": sa.get("uniqueId"),
                        "displayName": sa.get("displayName"),
                    },
                )
            )

    def _add_explicit_identities(self, snapshot: dict[str, Any], model: AccountModel) -> None:
        identities = snapshot.get("identities", {}) or {}
        for user in identities.get("users", []) or []:
            email = user if isinstance(user, str) else user.get("email") or user.get("primaryEmail")
            if email:
                model.add_principal(Principal(id=f"user:{email}", name=email, kind=USER))
        for group in identities.get("groups", []) or []:
            email = group if isinstance(group, str) else group.get("email") or group.get("primaryEmail")
            if email:
                model.add_principal(Principal(id=f"group:{email}", name=email, kind=GROUP))

    def _add_roles(self, snapshot: dict[str, Any], model: AccountModel) -> dict[str, Policy]:
        index: dict[str, Policy] = {}
        for role in snapshot.get("predefinedRoles", []) or []:
            index.update(self._add_role(role, model))
        for role in snapshot.get("customRoles", []) or snapshot.get("roles", []) or []:
            index.update(self._add_role(role, model))
        return index

    @staticmethod
    def _add_role(role: dict[str, Any], model: AccountModel) -> dict[str, Policy]:
        name = role.get("name") or role.get("title") or "<unknown role>"
        permissions = role.get("includedPermissions", []) or []
        categories = analyze_gcp_role(permissions)
        policy = Policy(
            id=str(name),
            name=str(name),
            categories=categories.result(),
            metadata={
                "roleType": _role_type(str(name)),
                "stage": role.get("stage"),
                "title": role.get("title"),
                "Path": "/",
                # Full set of permissions the role grants.
                "IncludedPermissions": list(permissions),
                "PolicyVersionList": [
                    {
                        "Document": {"includedPermissions": list(permissions)},
                        "VersionId": "v1",
                        "IsDefaultVersion": True,
                    }
                ],
            },
        )
        # The public list is part of the GCP contract even when empty.
        policy.attached_to.setdefault("public", [])
        model.add_policy(policy)
        return {str(name): policy}

    # --------------------------------------------------------------- bindings
    def _apply_bindings(self, snapshot: dict[str, Any], model: AccountModel, role_index: dict[str, Policy]) -> None:
        for binding in snapshot.get("bindings", []) or []:
            role_name = binding.get("role")
            if not role_name:
                continue
            policy = role_index.get(role_name)
            if policy is None:
                # Role not in the snapshot's role lists (e.g. a predefined role we
                # didn't expand): create a reference policy so the binding still
                # shows up. Basic roles are flagged via PublicAccess/metadata below.
                policy = self._reference_policy(role_name, model)

            for member in binding.get("members", []) or []:
                if _norm(member) in c.PUBLIC_MEMBERS:
                    if member not in policy.attached_to["public"]:
                        policy.attached_to["public"].append(member)
                    self._flag_public(policy, member)
                    continue
                principal = self._resolve_member(member, model)
                if principal is None:
                    continue
                model.attach(principal, policy)

    @staticmethod
    def _reference_policy(role_name: str, model: AccountModel) -> Policy:
        existing = model.policies.get(role_name)
        if existing is not None:
            return existing
        # Basic roles get a baseline finding even without permission expansion.
        from cloudsplaining.multicloud.analysis import Categories

        cats = Categories()
        if role_name in c.BASIC_ROLES:
            severity = c.BASIC_ROLES[role_name].lower()
            if role_name == "roles/owner":
                cats.add_privesc("critical", "basic role grants project-wide owner", [role_name])
            else:
                cats.add("InfrastructureModification", severity, [role_name])
        elif role_name in c.PRIVILEGED_PREDEFINED_ROLES:
            cats.add_privesc("high", "privilege-escalation predefined role", [role_name])
        policy = Policy(
            id=role_name,
            name=role_name,
            categories=cats.result(),
            metadata={
                "roleType": _role_type(role_name),
                "Path": "/",
                "PolicyVersionList": [
                    {
                        "Document": {"includedPermissions": []},
                        "VersionId": "v1",
                        "IsDefaultVersion": True,
                    }
                ],
            },
        )
        policy.attached_to.setdefault("public", [])
        model.add_policy(policy)
        return policy

    @staticmethod
    def _flag_public(policy: Policy, member: str) -> None:
        block = policy.categories.setdefault(PUBLIC_ACCESS, {"severity": "none", "description": "", "findings": []})
        block["severity"] = "critical"
        if member not in block["findings"]:
            block["findings"].append(member)

    @staticmethod
    def _resolve_member(member: str, model: AccountModel) -> Principal | None:
        rest = member
        deleted = rest.startswith("deleted:")
        if deleted:
            rest = rest[len("deleted:") :]
        if ":" not in rest:
            return model.add_principal(
                Principal(id=member, name=member, kind=USER, metadata={"provider_kind": "unknown"})
            )
        member_type, value = rest.split(":", 1)
        member_type = member_type.lower()
        # Deleted members carry a "?uid=..." disambiguation suffix; the name is
        # the identity itself, the raw member string stays as the id.
        name = value.split("?uid=", 1)[0]

        if member_type in ("group", "domain"):
            existing = model.get_principal(GROUP, member)
            if existing is not None:
                return existing
            group_metadata: dict[str, Any] = {"deleted": True} if deleted else {}
            return model.add_principal(Principal(id=member, name=name, kind=GROUP, metadata=group_metadata))

        metadata: dict[str, Any] = {}
        if member_type == "serviceaccount":
            metadata["provider_kind"] = "service_account"
        elif member_type != "user":
            metadata["provider_kind"] = "unknown"
        if deleted:
            metadata["deleted"] = True
        existing = model.get_principal(USER, member)
        if existing is not None:
            return existing
        return model.add_principal(Principal(id=member, name=name, kind=USER, metadata=metadata))
