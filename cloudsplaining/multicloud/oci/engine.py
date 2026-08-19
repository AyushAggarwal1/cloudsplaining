"""OCI engine: build an :class:`AccountModel` from an OCI IAM snapshot.

Snapshot schema (all keys optional; parsed JSON)::

    {
      "users":            [ {"id": ..., "name": ...} ],
      "groups":           [ {"id": ..., "name": ...} ],
      "dynamicGroups":    [ {"id": ..., "name": ...} ],   # workload identities -> roles
      "policies":         [ {"name": ..., "statements": [...], "compartmentId": ...} ],
      "groupMemberships": { "<groupName>": ["<userName>", ...] }
    }

Backward compatibility: a bare list of statement strings, a list of policy
objects, or ``{"statements": [...]}`` / ``{"policies": [...]}`` all work, with
empty identity collections.
"""

# Copyright (c) 2020, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
from __future__ import annotations

from typing import Any

from cloudsplaining.multicloud.analysis import Categories, analyze_oci_statements
from cloudsplaining.multicloud.model import (
    CUSTOMER,
    GROUP,
    ROLE,
    USER,
    AccountModel,
    Policy,
    Principal,
)
from cloudsplaining.multicloud.oci.parser import ParsedStatement, parse_statement
from cloudsplaining.multicloud.provider import Provider


class OciProvider(Provider):
    name = "oci"

    def scan(self, data: Any) -> AccountModel:
        snapshot = self._normalize(data)
        model = AccountModel(self.name, account_id=str(snapshot.get("account_id") or ""))

        self._add_identities(snapshot, model)
        self._add_memberships(snapshot, model)
        self._add_policies(snapshot, model)

        return model

    # ------------------------------------------------------------------ input
    @staticmethod
    def _normalize(data: Any) -> dict[str, Any]:
        if isinstance(data, list):
            # Bare list of statement strings, or list of policy objects.
            if all(isinstance(i, str) for i in data):
                return {"policies": [{"name": "<inline>", "statements": data}]}
            return {"policies": data}
        if isinstance(data, dict):
            snapshot = dict(data)
            if "policies" not in snapshot and "statements" in snapshot:
                snapshot["policies"] = [{"name": "<inline>", "statements": snapshot["statements"]}]
            return snapshot
        raise ValueError("OCI input must be a list of statements/policies or a snapshot object.")

    # ------------------------------------------------------------- identities
    def _add_identities(self, snapshot: dict[str, Any], model: AccountModel) -> None:
        for user in snapshot.get("users", []) or []:
            uid, name = self._id_name(user)
            model.add_principal(Principal(id=uid, name=name, kind=USER, metadata=self._meta(user)))
        for group in snapshot.get("groups", []) or []:
            gid, name = self._id_name(group)
            model.add_principal(Principal(id=gid, name=name, kind=GROUP, metadata=self._meta(group)))
        for dgroup in snapshot.get("dynamicGroups", []) or []:
            did, name = self._id_name(dgroup)
            model.add_principal(
                Principal(id=did, name=name, kind=ROLE, metadata={"matchingRule": _get(dgroup, "matching-rule")})
            )

    def _add_memberships(self, snapshot: dict[str, Any], model: AccountModel) -> None:
        for group_name, members in (snapshot.get("groupMemberships", {}) or {}).items():
            group = self._find_by_name(model, GROUP, group_name)
            for member in members:
                user = self._find_by_name(model, USER, member)
                if user is not None and group is not None and group.name not in user.groups:
                    user.groups.append(group.name)

    # --------------------------------------------------------------- policies
    def _add_policies(self, snapshot: dict[str, Any], model: AccountModel) -> None:
        for policy_obj in snapshot.get("policies", []) or []:
            name = policy_obj.get("name", "<policy>")
            policy_id = policy_obj.get("id") or name
            statements = policy_obj.get("statements", []) or []

            parsed: list[ParsedStatement] = []
            for raw in statements:
                p = parse_statement(raw, name)
                if p is not None:
                    parsed.append(p)

            categories = analyze_oci_statements(parsed)
            granted = [f"{p.verb} {p.resource} in {p.location}" for p in parsed]
            policy = Policy(
                id=str(policy_id),
                name=str(name),
                kind=CUSTOMER,
                categories=categories.result(),
                metadata={
                    "compartmentId": policy_obj.get("compartmentId"),
                    "statements": statements,
                    "GrantedAccess": granted,
                    "Path": "/",
                    "PolicyVersionList": [
                        {
                            "Document": {"statements": statements},
                            "VersionId": "v1",
                            "IsDefaultVersion": True,
                        }
                    ],
                },
            )
            model.add_policy(policy)
            self._attach_subjects(parsed, policy, model)

    def _attach_subjects(self, parsed: list[ParsedStatement], policy: Policy, model: AccountModel) -> None:
        for stmt in parsed:
            if stmt.subject_type == "any-user":
                continue
            name = stmt.subject.strip()
            if not name:
                continue
            kind = ROLE if stmt.subject_type == "dynamic-group" else GROUP
            principal = self._find_by_name(model, kind, name)
            if principal is None:
                principal = model.add_principal(Principal(id=f"{stmt.subject_type}:{name}", name=name, kind=kind))
            model.attach(principal, policy)

    # ----------------------------------------------------------------- helpers
    @staticmethod
    def _id_name(obj: Any) -> tuple[str, str]:
        if isinstance(obj, str):
            return obj, obj
        oid = obj.get("id") or obj.get("name")
        name = obj.get("name") or obj.get("id")
        return str(oid), str(name)

    @staticmethod
    def _meta(obj: Any) -> dict[str, Any]:
        if not isinstance(obj, dict):
            return {}
        return {"description": obj.get("description"), "compartmentId": obj.get("compartmentId")}

    @staticmethod
    def _find_by_name(model: AccountModel, kind: str, name: str) -> Principal | None:
        bucket = {USER: model.users, GROUP: model.groups, ROLE: model.roles}[kind]
        for principal in bucket.values():
            if principal.name.lower() == name.lower():
                return principal
        return None


def _get(obj: Any, key: str) -> Any:
    return obj.get(key) if isinstance(obj, dict) else None
