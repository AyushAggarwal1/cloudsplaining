"""Build a permission-set -> principals -> actions access map from a multi-cloud report.

Given the report dict produced by
:func:`cloudsplaining.multicloud.serialize.render`, this flattens every
permission set (the ``roles`` collection for Azure/GCP, ``policies`` for OCI)
into a row describing:

* which users / groups (and public members, for GCP) it is attached to, and
* the full set of actions/permissions it grants.

The granted actions are read from whichever provider-specific metadata field the
engine stored: Azure ``Actions``/``DataActions``, GCP ``IncludedPermissions``, or
OCI ``GrantedAccess`` (falling back to ``statements``).
"""

# Copyright (c) 2020, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
from __future__ import annotations

import csv
import io
from typing import Any

from cloudsplaining.multicloud.serialize import permission_collection_key

_RANK = {"none": 0, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_CATEGORIES = (
    "PrivilegeEscalation",
    "DataExfiltration",
    "ResourceExposure",
    "ServiceWildcard",
    "CredentialsExposure",
    "InfrastructureModification",
    "PublicAccess",
    "OverlyBroadScope",
)


def _granted_actions(entry: dict[str, Any]) -> list[str]:
    """Return every action/permission the policy grants, provider-agnostic."""
    actions: list[str] = []
    for field in ("Actions", "DataActions", "IncludedPermissions", "GrantedAccess"):
        value = entry.get(field)
        if isinstance(value, list):
            actions.extend(str(v) for v in value)
    if not actions and isinstance(entry.get("statements"), list):
        actions.extend(str(v) for v in entry["statements"])
    # De-dupe, preserve order.
    seen: set[str] = set()
    ordered: list[str] = []
    for action in actions:
        if action not in seen:
            seen.add(action)
            ordered.append(action)
    return ordered


def _worst_severity(entry: dict[str, Any]) -> str:
    worst = "none"
    for category in _CATEGORIES:
        block = entry.get(category) or {}
        if block.get("findings") and _RANK.get(block.get("severity", "none"), 0) > _RANK[worst]:
            worst = block["severity"]
    return worst


def build(report: dict[str, Any], only_attached: bool = False) -> list[dict[str, Any]]:
    """Return one row per permission set. ``only_attached`` drops unattached ones."""
    provider = report.get("provider", "")
    collection = permission_collection_key(provider)
    rows: list[dict[str, Any]] = []
    for entry in report.get(collection, {}).values():
        attached = entry.get("AttachedTo", {}) or {}
        users = list(attached.get("users", []))
        groups = list(attached.get("groups", []))
        public = list(attached.get("public", []))
        if only_attached and not (users or groups or public):
            continue
        actions = _granted_actions(entry)
        rows.append(
            {
                "provider": provider,
                "policyType": entry.get("roleType") or entry.get("policyType") or collection,
                "policyName": entry.get("RoleName") or entry.get("PolicyName") or "?",
                "policyId": entry.get("RoleId") or entry.get("PolicyId") or "",
                "severity": _worst_severity(entry),
                "users": users,
                "groups": groups,
                "public": public,
                "attachmentCount": entry.get("AttachmentCount", 0),
                "actionCount": len(actions),
                "actions": actions,
            }
        )
    rows.sort(key=lambda r: (-_RANK.get(r["severity"], 0), -r["attachmentCount"], r["policyName"]))
    return rows


def render_json(rows: list[dict[str, Any]]) -> str:
    import json

    return json.dumps(rows, indent=2, default=str)


def render_csv(rows: list[dict[str, Any]]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        ["provider", "policyType", "policyName", "severity", "users", "groups", "public", "actionCount", "actions"]
    )
    for row in rows:
        writer.writerow(
            [
                row["provider"],
                row["policyType"],
                row["policyName"],
                row["severity"],
                "; ".join(row["users"]),
                "; ".join(row["groups"]),
                "; ".join(row["public"]),
                row["actionCount"],
                "; ".join(row["actions"]),
            ]
        )
    return buffer.getvalue()


def render_console(rows: list[dict[str, Any]], max_actions: int = 15) -> str:
    lines: list[str] = []
    for row in rows:
        lines.append(f"[{row['severity'].upper()}] {row['policyName']}  ({row['policyType']})")
        attached = []
        if row["users"]:
            attached.append(f"users: {', '.join(row['users'])}")
        if row["groups"]:
            attached.append(f"groups: {', '.join(row['groups'])}")
        if row["public"]:
            attached.append(f"public: {', '.join(row['public'])}")
        lines.append(f"  AttachedTo : {' | '.join(attached) or 'unattached'}")
        actions = row["actions"]
        shown = ", ".join(actions[:max_actions])
        if len(actions) > max_actions:
            shown += f", ... (+{len(actions) - max_actions} more)"
        lines.append(f"  Actions ({row['actionCount']}): {shown or '(none recorded)'}")
        lines.append("")
    if not lines:
        return "No policies found."
    return "\n".join(lines)
