"""GCP IAM collector.

Pulls service accounts + custom roles from the IAM API, the project IAM policy
(bindings) from Resource Manager, and expands any predefined roles referenced by
the bindings. Returns the snapshot dict the GCP engine consumes.

Requires ``pip install 'cloudsplaining[gcp]'`` (google-api-python-client,
google-auth). Authentication uses Application Default Credentials.
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


class GcpCollector(Collector):
    name = "gcp"
    extra = "gcp"

    def __init__(self, project_id: str, **_: Any) -> None:
        if not project_id:
            raise ValueError("GCP collector requires a project_id.")
        self.project_id = project_id
        self._iam: Any | None = None
        self._crm: Any | None = None

    def _build(self, service: str, version: str) -> Any:
        discovery = self._import("googleapiclient.discovery")
        return discovery.build(service, version, cache_discovery=False)

    def iam(self) -> Any:
        if self._iam is None:
            self._iam = self._build("iam", "v1")
        return self._iam

    def crm(self) -> Any:
        if self._crm is None:
            self._crm = self._build("cloudresourcemanager", "v1")
        return self._crm

    def collect(self) -> dict[str, Any]:
        bindings = self._bindings()
        snapshot: dict[str, Any] = {
            "serviceAccounts": self._service_accounts(),
            "customRoles": self._custom_roles(),
            "predefinedRoles": self._predefined_roles(bindings),
            "bindings": bindings,
        }
        return snapshot

    # --------------------------------------------------------------- resources
    def _service_accounts(self) -> list[dict[str, Any]]:
        name = f"projects/{self.project_id}"
        out: list[dict[str, Any]] = []
        request = self.iam().projects().serviceAccounts().list(name=name)
        while request is not None:
            resp = request.execute()
            for sa in resp.get("accounts", []):
                out.append(
                    {"email": sa.get("email"), "uniqueId": sa.get("uniqueId"), "displayName": sa.get("displayName")}
                )
            request = self.iam().projects().serviceAccounts().list_next(request, resp)
        return out

    def _custom_roles(self) -> list[dict[str, Any]]:
        parent = f"projects/{self.project_id}"
        out: list[dict[str, Any]] = []
        request = self.iam().projects().roles().list(parent=parent, view="FULL")
        while request is not None:
            resp = request.execute()
            for role in resp.get("roles", []):
                out.append(
                    {
                        "name": role.get("name"),
                        "title": role.get("title"),
                        "stage": role.get("stage"),
                        "includedPermissions": role.get("includedPermissions", []),
                    }
                )
            request = self.iam().projects().roles().list_next(request, resp)
        return out

    def _bindings(self) -> list[dict[str, Any]]:
        body = {"options": {"requestedPolicyVersion": 3}}
        policy = self.crm().projects().getIamPolicy(resource=self.project_id, body=body).execute()
        resource = f"projects/{self.project_id}"
        out: list[dict[str, Any]] = []
        for binding in policy.get("bindings", []):
            entry = {
                "role": binding.get("role"),
                "members": list(binding.get("members", [])),
                "resource": resource,
            }
            if binding.get("condition"):
                entry["condition"] = binding["condition"]
            out.append(entry)
        return out

    def _predefined_roles(self, bindings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        names = {b["role"] for b in bindings if str(b.get("role", "")).startswith("roles/")}
        out: list[dict[str, Any]] = []
        for role_name in sorted(names):
            try:
                role = self.iam().roles().get(name=role_name).execute()
            except Exception as error:  # pragma: no cover - network dependent
                logger.warning("Could not expand predefined role %s: %s", role_name, error)
                continue
            out.append(
                {
                    "name": role.get("name"),
                    "title": role.get("title"),
                    "includedPermissions": role.get("includedPermissions", []),
                }
            )
        return out
