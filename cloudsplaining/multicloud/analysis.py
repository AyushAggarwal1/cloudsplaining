"""Per-policy risk analysis shared by every provider.

Each ``analyze_*`` function takes one policy's raw permissions (Azure
actions/dataActions, GCP includedPermissions, or OCI statements) and returns the
AWS-style category map::

    {category: {"severity": <str>, "description": <str>, "findings": [...]}}

``PrivilegeEscalation`` findings use the AWS ``{"type": ..., "actions": [...]}``
shape; every other category uses a flat list of permission strings. The risk
sets themselves live in the per-provider ``constants.py`` modules and are reused
here unchanged.
"""

# Copyright (c) 2020, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
from __future__ import annotations

from fnmatch import fnmatch
from typing import Any

from cloudsplaining.multicloud.azure import constants as az
from cloudsplaining.multicloud.findings import (
    CREDENTIALS_EXPOSURE,
    DATA_EXFILTRATION,
    INFRASTRUCTURE_MODIFICATION,
    OVERLY_BROAD_SCOPE,
    PRIVILEGE_ESCALATION,
    PUBLIC_ACCESS,
    RESOURCE_EXPOSURE,
    SERVICE_WILDCARD,
)
from cloudsplaining.multicloud.gcp import constants as gc
from cloudsplaining.multicloud.oci import constants as oc

CATEGORY_ORDER = [
    PRIVILEGE_ESCALATION,
    DATA_EXFILTRATION,
    RESOURCE_EXPOSURE,
    SERVICE_WILDCARD,
    CREDENTIALS_EXPOSURE,
    INFRASTRUCTURE_MODIFICATION,
    PUBLIC_ACCESS,
    OVERLY_BROAD_SCOPE,
]

CATEGORY_DESCRIPTION = {
    PRIVILEGE_ESCALATION: "Permissions that let a principal grant themselves additional access "
    "(e.g. writing role assignments, setting IAM policy, impersonating service accounts, or "
    "managing identity resources).",
    DATA_EXFILTRATION: "Permissions that allow bulk reads of data (object storage, databases, "
    "BigQuery, etc.) without resource constraints, enabling data exfiltration.",
    RESOURCE_EXPOSURE: "Permissions that modify resource access policies and can expose resources "
    "publicly (IAM policy on resources, firewall/network rules, access policies).",
    SERVICE_WILDCARD: "Grants that use a wildcard to allow ALL actions of a service/provider "
    "(e.g. '*' or 'Microsoft.Compute/*').",
    CREDENTIALS_EXPOSURE: "Permissions that return or mint reusable credentials (service account "
    "keys, storage keys, Key Vault/Secret Manager secrets).",
    INFRASTRUCTURE_MODIFICATION: "Broad create/update/delete permissions over infrastructure "
    "beyond least-privilege needs.",
    PUBLIC_ACCESS: "Grants to public principals (allUsers / allAuthenticatedUsers / any-user) that "
    "expose resources to anyone.",
    OVERLY_BROAD_SCOPE: "Grants applied at an excessively broad scope (tenant root, tenancy-wide, "
    "or unconditioned) relative to what is needed.",
}

_SEVERITY_RANK = {"none": 0, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _rank(severity: str) -> int:
    return _SEVERITY_RANK.get(severity, 0)


class Categories:
    """Accumulates findings into the AWS-style category map."""

    def __init__(self) -> None:
        self.blocks: dict[str, dict[str, Any]] = {
            cat: {"severity": "none", "description": CATEGORY_DESCRIPTION[cat], "findings": []}
            for cat in CATEGORY_ORDER
        }

    def add(self, category: str, severity: str, items: list[str]) -> None:
        block = self.blocks[category]
        if _rank(severity) > _rank(block["severity"]):
            block["severity"] = severity
        for item in items:
            if item not in block["findings"]:
                block["findings"].append(item)

    def add_privesc(self, severity: str, type_label: str, actions: list[str]) -> None:
        block = self.blocks[PRIVILEGE_ESCALATION]
        if _rank(severity) > _rank(block["severity"]):
            block["severity"] = severity
        block["findings"].append({"type": type_label, "actions": actions})

    def result(self) -> dict[str, dict[str, Any]]:
        return self.blocks

    def has_findings(self) -> bool:
        return any(b["findings"] for b in self.blocks.values())


def _norm(value: str) -> str:
    return value.strip().lower()


# --------------------------------------------------------------------- Azure
def _az_grants(patterns: list[str], target: str, not_actions: set[str]) -> bool:
    target = _norm(target)
    if target in not_actions or any(fnmatch(target, na) for na in not_actions):
        return False
    return any(fnmatch(target, _norm(p)) for p in patterns)


def _az_matched(patterns: list[str], targets: set[str], not_actions: set[str]) -> list[str]:
    return sorted(t for t in targets if _az_grants(patterns, t, not_actions))


def analyze_azure_role(
    actions: list[str],
    data_actions: list[str],
    not_actions: set[str],
    assignable_scopes: list[str] | None = None,
) -> Categories:
    cats = Categories()
    norm_actions = [_norm(a) for a in actions]

    if any(a == "*" for a in norm_actions):
        cats.add(SERVICE_WILDCARD, "critical", ["*"])

    priv = _az_matched(actions, az.PRIVILEGE_ESCALATION_ACTIONS, not_actions)
    priv += [p for p in az.PRIVILEGE_ESCALATION_WILDCARDS if p in norm_actions]
    if priv:
        cats.add_privesc("critical", "RBAC role / assignment management", sorted(set(priv)))

    creds = _az_matched(actions, az.CREDENTIALS_EXPOSURE_ACTIONS, not_actions)
    if creds:
        cats.add(CREDENTIALS_EXPOSURE, "high", creds)

    exposure = _az_matched(actions, az.RESOURCE_EXPOSURE_ACTIONS, not_actions)
    if exposure:
        cats.add(RESOURCE_EXPOSURE, "high", exposure)

    exfil = sorted(t for t in az.DATA_EXFILTRATION_DATA_ACTIONS if _az_grants(data_actions, t, set()))
    if any(_norm(a) == "*" for a in data_actions):
        exfil = ["*"] + exfil
    if exfil:
        cats.add(DATA_EXFILTRATION, "high", exfil)

    service_wildcards = sorted(
        a for a in norm_actions if a != "*" and a.endswith("/*") and not a.startswith("microsoft.authorization")
    )
    if service_wildcards:
        cats.add(INFRASTRUCTURE_MODIFICATION, "medium", service_wildcards)

    scopes = assignable_scopes or []
    if _azure_has_root_scope(scopes) and (any(_norm(a) == "*" for a in norm_actions) or service_wildcards):
        cats.add(OVERLY_BROAD_SCOPE, "high", ["assignableScopes:/"])

    return cats


def _azure_has_root_scope(scopes: list[str]) -> bool:
    for scope in scopes:
        stripped = scope.strip()
        if stripped == az.ROOT_SCOPE:
            return True
        if stripped.startswith("/providers/Microsoft.Management/managementGroups/") and stripped.count("/") <= 4:
            return True
    return False


# ----------------------------------------------------------------------- GCP
def analyze_gcp_role(permissions: list[str]) -> Categories:
    cats = Categories()
    perm_set = {_norm(p) for p in permissions}

    priv = sorted(
        p for p in perm_set if p in gc.PRIVILEGE_ESCALATION_PERMISSIONS or p.endswith(gc.SET_IAM_POLICY_SUFFIX)
    )
    if priv:
        cats.add_privesc("critical", "IAM policy / service-account impersonation", priv)

    creds = sorted(perm_set & gc.CREDENTIALS_EXPOSURE_PERMISSIONS)
    if creds:
        cats.add(CREDENTIALS_EXPOSURE, "high", creds)

    exposure = sorted(perm_set & gc.RESOURCE_EXPOSURE_PERMISSIONS)
    if exposure:
        cats.add(RESOURCE_EXPOSURE, "high", exposure)

    exfil = sorted(perm_set & gc.DATA_EXFILTRATION_PERMISSIONS)
    if exfil:
        cats.add(DATA_EXFILTRATION, "medium", exfil)

    return cats


# ----------------------------------------------------------------------- OCI
def analyze_oci_statements(parsed: list[Any]) -> Categories:
    """Given parsed OCI statements (see oci.engine.parse_statement), build categories."""
    cats = Categories()
    for s in parsed:
        _oci_eval_statement(s, cats)
    return cats


def _oci_eval_statement(s: Any, cats: Categories) -> None:
    perm = f"{s.verb} {s.resource}"
    is_manage = s.verb == "manage"
    is_write = s.verb_level >= oc.VERB_LEVELS["use"]

    if s.subject_type == "any-user":
        cats.add(PUBLIC_ACCESS, "critical" if is_manage else "high", [perm])

    if is_manage and s.resource == "all-resources":
        if s.is_tenancy:
            cats.add_privesc("critical", "manage all-resources in tenancy", [perm])
        else:
            cats.add(INFRASTRUCTURE_MODIFICATION, "high", [perm])
    elif is_manage and s.resource in oc.IDENTITY_RESOURCE_TYPES:
        cats.add_privesc("critical" if s.is_tenancy else "high", f"manage {s.resource}", [perm])
    elif is_manage and s.resource in oc.BROAD_RESOURCE_FAMILIES:
        cats.add(INFRASTRUCTURE_MODIFICATION, "high" if s.is_tenancy else "medium", [perm])

    if is_write and s.resource in oc.CREDENTIALS_RESOURCE_TYPES:
        cats.add(CREDENTIALS_EXPOSURE, "high", [perm])

    if s.verb_level >= oc.VERB_LEVELS["read"] and s.resource in oc.DATA_RESOURCE_TYPES and not s.condition:
        cats.add(DATA_EXFILTRATION, "medium", [perm])

    if is_manage and s.resource in oc.EXPOSURE_RESOURCE_TYPES:
        cats.add(RESOURCE_EXPOSURE, "medium", [perm])

    if (
        is_manage
        and s.is_tenancy
        and not s.condition
        and s.resource not in oc.BROAD_RESOURCE_FAMILIES
        and s.resource not in oc.IDENTITY_RESOURCE_TYPES
        and s.resource != "all-resources"
    ):
        cats.add(OVERLY_BROAD_SCOPE, "low", [perm])
