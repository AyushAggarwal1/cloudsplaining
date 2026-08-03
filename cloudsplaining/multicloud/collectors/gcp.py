"""GCP IAM collector.

Pulls service accounts + custom roles from the IAM API, the project IAM policy
(bindings) from Resource Manager, and expands any predefined roles referenced by
the bindings. Returns the snapshot dict the GCP engine consumes.

Also collects the optional identity-lifecycle enrichment the inventory builder
understands (see ``cloudsplaining/identity_inventory/gcp.py``):

- ``serviceAccountActivities`` — Policy Analyzer ``serviceAccountLastAuthentication``
  (needs ``policyanalyzer.serviceAccountLastAuthenticationActivities.query``,
  e.g. ``roles/policyanalyzer.activityAnalysisViewer``).
- ``auditLogEntries`` — Admin Activity audit logs (needs
  ``logging.logEntries.list``, e.g. ``roles/logging.viewer``).

Both fail open: if the caller lacks the permission or the API is disabled, the
key is emitted as an empty list and the corresponding inventory fields stay null.

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
from collections.abc import Callable
from typing import Any

from cloudsplaining.multicloud.collectors.base import Collector

logger = logging.getLogger(__name__)

#: Newest-first pages of general Admin Activity entries fetched for human
#: users' last_used; creation/grant events are fetched separately without a cap.
_ACTIVITY_PAGE_LIMIT = 3
#: The creation/grant pass scans the whole retention window server-side, which
#: on active projects yields many sparse pages; bound it so collect() finishes.
_GRANT_PAGE_LIMIT = 30
_PAGE_SIZE = 1000


class GcpCollector(Collector):
    name = "gcp"
    extra = "gcp"

    def __init__(self, project_id: str, **_: Any) -> None:
        if not project_id:
            raise ValueError("GCP collector requires a project_id.")
        self.project_id = project_id
        self._iam: Any | None = None
        self._crm: Any | None = None
        self._policy_analyzer: Any | None = None
        self._logging: Any | None = None

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

    def policy_analyzer(self) -> Any:
        if self._policy_analyzer is None:
            self._policy_analyzer = self._build("policyanalyzer", "v1")
        return self._policy_analyzer

    def logging_client(self) -> Any:
        if self._logging is None:
            self._logging = self._build("logging", "v2")
        return self._logging

    def collect(self) -> dict[str, Any]:
        bindings = self._bindings()
        snapshot: dict[str, Any] = {
            "serviceAccounts": self._service_accounts(),
            "customRoles": self._custom_roles(),
            "predefinedRoles": self._predefined_roles(bindings),
            "bindings": bindings,
            "serviceAccountActivities": self._optional("serviceAccountActivities", self._service_account_activities),
            "auditLogEntries": self._optional("auditLogEntries", self._audit_log_entries),
        }
        return snapshot

    def _optional(self, key: str, fetch: Callable[[], list[dict[str, Any]]]) -> list[dict[str, Any]]:
        try:
            return fetch()
        except Exception as error:
            logger.warning("Skipping %s (lifecycle fields will be null): %s", key, error)
            return []

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

    # ------------------------------------------------------------- lifecycle
    def _service_account_activities(self) -> list[dict[str, Any]]:
        parent = f"projects/{self.project_id}/locations/global/activityTypes/serviceAccountLastAuthentication"
        activities = self.policy_analyzer().projects().locations().activityTypes().activities()
        out: list[dict[str, Any]] = []
        request = activities.query(parent=parent, pageSize=_PAGE_SIZE)
        while request is not None:
            resp = request.execute()
            out.extend(resp.get("activities", []))
            request = activities.query_next(request, resp)
        return out

    def _audit_log_entries(self) -> list[dict[str, Any]]:
        log_filter = f'logName="projects/{self.project_id}/logs/cloudaudit.googleapis.com%2Factivity"'
        entries: list[dict[str, Any]] = []
        # Newest-first general activity, capped: enough to derive human users'
        # last_used without paging through the whole 400-day retention window.
        entries.extend(
            self._log_entries(
                {
                    "resourceNames": [f"projects/{self.project_id}"],
                    "filter": log_filter,
                    "orderBy": "timestamp desc",
                    "pageSize": _PAGE_SIZE,
                },
                page_limit=_ACTIVITY_PAGE_LIMIT,
            )
        )
        # Creation/grant events: created_at/created_by need the oldest
        # CreateServiceAccount and SetIamPolicy entries still retained.
        entries.extend(
            self._log_entries(
                {
                    "resourceNames": [f"projects/{self.project_id}"],
                    "filter": (
                        f'{log_filter} AND (protoPayload.methodName:"SetIamPolicy"'
                        ' OR protoPayload.methodName:"CreateServiceAccount")'
                    ),
                    "pageSize": _PAGE_SIZE,
                },
                page_limit=_GRANT_PAGE_LIMIT,
            )
        )
        return entries

    def _log_entries(self, body: dict[str, Any], page_limit: int | None = None) -> list[dict[str, Any]]:
        client = self.logging_client()
        out: list[dict[str, Any]] = []
        pages = 0
        request = client.entries().list(body=body)
        while request is not None and (page_limit is None or pages < page_limit):
            resp = request.execute()
            out.extend(resp.get("entries", []))
            request = client.entries().list_next(request, resp)
            pages += 1
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
