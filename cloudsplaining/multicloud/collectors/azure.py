"""Azure IAM collector.

Pulls role definitions + assignments from the Authorization management plane and
users/groups/service-principals from Microsoft Graph, returning the snapshot dict
the Azure engine consumes.

Requires ``pip install 'cloudsplaining[azure]'`` (azure-identity,
azure-mgmt-authorization, requests). Authentication uses ``DefaultAzureCredential``
(env vars, managed identity, az login, ...).
"""

# Copyright (c) 2020, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
from __future__ import annotations

import logging
from typing import Any

from cloudsplaining.multicloud.collectors.base import Collector

logger = logging.getLogger(__name__)

_GRAPH = "https://graph.microsoft.com/v1.0"
_GRAPH_SCOPE = "https://graph.microsoft.com/.default"


class AzureCollector(Collector):
    name = "azure"
    extra = "azure"

    def __init__(self, subscription_id: str | None = None, credential: Any | None = None, **_: Any) -> None:
        if not subscription_id:
            raise ValueError("Azure collector requires a subscription_id.")
        self.subscription_id = subscription_id
        self._credential = credential

    def credential(self) -> Any:
        if self._credential is None:
            identity = self._import("azure.identity")
            self._credential = identity.DefaultAzureCredential()
        return self._credential

    def collect(self) -> dict[str, Any]:
        snapshot: dict[str, Any] = {
            "roleDefinitions": self._role_definitions(),
            "roleAssignments": self._role_assignments(),
            "users": [],
            "groups": [],
            "servicePrincipals": [],
            "groupMemberships": {},
        }
        # Microsoft Graph is best-effort: a credential without Directory.Read.All
        # still yields a useful role-based report.
        try:
            self._collect_graph(snapshot)
        except Exception as error:  # pragma: no cover - network/permission dependent
            logger.warning("Skipping Microsoft Graph identity collection: %s", error)
        return snapshot

    # --------------------------------------------------------- management plane
    def _authorization_client(self) -> Any:
        auth = self._import("azure.mgmt.authorization")
        return auth.AuthorizationManagementClient(self.credential(), self.subscription_id)

    def _scope(self) -> str:
        return f"/subscriptions/{self.subscription_id}"

    def _role_definitions(self) -> list[dict[str, Any]]:
        client = self._authorization_client()
        out: list[dict[str, Any]] = []
        for rd in client.role_definitions.list(self._scope()):
            permissions = [
                {
                    "actions": list(p.actions or []),
                    "notActions": list(p.not_actions or []),
                    "dataActions": list(p.data_actions or []),
                    "notDataActions": list(p.not_data_actions or []),
                }
                for p in (rd.permissions or [])
            ]
            out.append(
                {
                    "id": rd.name,  # the GUID
                    "roleName": rd.role_name,
                    "roleType": rd.role_type,
                    "assignableScopes": list(rd.assignable_scopes or []),
                    "permissions": permissions,
                }
            )
        return out

    def _role_assignments(self) -> list[dict[str, Any]]:
        client = self._authorization_client()
        out: list[dict[str, Any]] = []
        for ra in client.role_assignments.list_for_subscription():
            out.append(
                {
                    "principalId": ra.principal_id,
                    "principalType": ra.principal_type,
                    "roleDefinitionId": ra.role_definition_id,
                    "scope": ra.scope,
                }
            )
        return out

    # ------------------------------------------------------------------- Graph
    def _collect_graph(self, snapshot: dict[str, Any]) -> None:
        token = self.credential().get_token(_GRAPH_SCOPE).token
        snapshot["users"] = self._graph_list(token, "/users?$select=id,userPrincipalName,displayName,accountEnabled")
        snapshot["groups"] = self._graph_list(token, "/groups?$select=id,displayName")
        snapshot["servicePrincipals"] = self._graph_list(
            token, "/servicePrincipals?$select=id,appId,displayName,servicePrincipalType"
        )
        memberships: dict[str, list[str]] = {}
        for group in snapshot["groups"]:
            gid = group["id"]
            members = self._graph_list(token, f"/groups/{gid}/members?$select=id")
            memberships[gid] = [m["id"] for m in members if "id" in m]
        snapshot["groupMemberships"] = memberships

    def _graph_list(self, token: str, path: str) -> list[dict[str, Any]]:
        requests = self._import("requests")
        headers = {"Authorization": f"Bearer {token}"}
        url = f"{_GRAPH}{path}"
        results: list[dict[str, Any]] = []
        while url:
            resp = requests.get(url, headers=headers, timeout=30)
            resp.raise_for_status()
            body = resp.json()
            results.extend(body.get("value", []))
            url = body.get("@odata.nextLink")
        return results
