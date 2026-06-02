"""OCI IAM collector.

Pulls users, groups, dynamic-groups, policies, and group memberships from the
OCI Identity service, returning the snapshot dict the OCI engine consumes.

Requires ``pip install 'cloudsplaining[oci]'`` (oci). Authentication uses the
standard OCI config file (``~/.oci/config``) / instance principals.
"""

# Copyright (c) 2020, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
from __future__ import annotations

from typing import Any

from cloudsplaining.multicloud.collectors.base import Collector


class OciCollector(Collector):
    name = "oci"
    extra = "oci"

    def __init__(
        self,
        tenancy_id: str | None = None,
        config_profile: str = "DEFAULT",
        client: Any | None = None,
        **_: Any,
    ) -> None:
        self._tenancy_id = tenancy_id
        self._config_profile = config_profile
        self._client = client

    def client(self) -> tuple[Any, str]:
        """Return (IdentityClient, tenancy_ocid)."""
        if self._client is not None:
            return self._client, (self._tenancy_id or "")
        oci = self._import("oci")
        config = oci.config.from_file(profile_name=self._config_profile)
        tenancy = self._tenancy_id or config["tenancy"]
        return oci.identity.IdentityClient(config), tenancy

    def collect(self) -> dict[str, Any]:
        client, tenancy = self.client()
        users = self._list(client.list_users, tenancy)
        groups = self._list(client.list_groups, tenancy)
        dynamic_groups = self._list(client.list_dynamic_groups, tenancy)
        policies = self._policies(client, tenancy)
        memberships = self._memberships(client, tenancy, users, groups)

        return {
            "users": [self._user(u) for u in users],
            "groups": [self._named(g) for g in groups],
            "dynamicGroups": [self._dynamic_group(d) for d in dynamic_groups],
            "policies": policies,
            "groupMemberships": memberships,
        }

    # ----------------------------------------------------------------- helpers
    @staticmethod
    def _list(fn: Any, compartment_id: str) -> list[Any]:
        # OCI list_* calls are paginated; oci.pagination.list_call_get_all_results
        # is the idiomatic helper, but we page manually to avoid importing it.
        items: list[Any] = []
        page = None
        while True:
            resp = fn(compartment_id, page=page) if page else fn(compartment_id)
            items.extend(resp.data)
            page = resp.next_page
            if not page:
                break
        return items

    def _policies(self, client: Any, tenancy: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        # Policies can live in any compartment; collect the tenancy plus its
        # immediate compartments. Callers needing the full tree can pre-build a
        # snapshot; this covers the common flat layout.
        compartments = [tenancy] + [c.id for c in self._list(client.list_compartments, tenancy)]
        for compartment_id in compartments:
            for policy in self._list(client.list_policies, compartment_id):
                out.append(
                    {
                        "id": policy.id,
                        "name": policy.name,
                        "compartmentId": policy.compartment_id,
                        "statements": list(policy.statements or []),
                    }
                )
        return out

    def _memberships(
        self, client: Any, tenancy: str, users: list[Any], groups: list[Any]
    ) -> dict[str, list[str]]:
        user_name = {u.id: u.name for u in users}
        memberships: dict[str, list[str]] = {}
        for group in groups:
            links = self._list_memberships(client, tenancy, group.id)
            names = [user_name.get(link.user_id) for link in links]
            memberships[group.name] = [n for n in names if n]
        return memberships

    def _list_memberships(self, client: Any, tenancy: str, group_id: str) -> list[Any]:
        items: list[Any] = []
        page = None
        while True:
            kwargs = {"compartment_id": tenancy, "group_id": group_id}
            if page:
                kwargs["page"] = page
            resp = client.list_user_group_memberships(**kwargs)
            items.extend(resp.data)
            page = resp.next_page
            if not page:
                break
        return items

    @staticmethod
    def _named(obj: Any) -> dict[str, Any]:
        return {"id": obj.id, "name": obj.name, "description": getattr(obj, "description", None)}

    @staticmethod
    def _user(obj: Any) -> dict[str, Any]:
        return {"id": obj.id, "name": obj.name, "description": getattr(obj, "description", None)}

    @staticmethod
    def _dynamic_group(obj: Any) -> dict[str, Any]:
        return {"id": obj.id, "name": obj.name, "matching-rule": getattr(obj, "matching_rule", None)}
