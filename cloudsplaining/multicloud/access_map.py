"""Build a policy -> principals -> actions access map from a multi-cloud report.

Given the report dict produced by
:func:`cloudsplaining.multicloud.report_aws.render`, this flattens every policy
(across ``aws_managed_policies`` / ``customer_managed_policies`` /
``inline_policies``) into a row describing:

* which users / groups / roles the policy is attached to (``AttachedTo``), and
* the full set of actions/permissions the policy grants.

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

from cloudsplaining.multicloud.report_aws import policy_collection_keys

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
    """Return one row per policy. ``only_attached`` drops unattached policies."""
    provider = report.get("provider", "")
    rows: list[dict[str, Any]] = []
    for collection in policy_collection_keys(report):
        for entry in report.get(collection, {}).values():
            attached = entry.get("AttachedTo", {}) or {}
            users = list(attached.get("users", []))
            groups = list(attached.get("groups", []))
            roles = list(attached.get("roles", []))
            if only_attached and not (users or groups or roles):
                continue
            actions = _granted_actions(entry)
            rows.append(
                {
                    "provider": provider,
                    "policyType": collection,
                    "policyName": entry.get("PolicyName", "?"),
                    "policyId": entry.get("PolicyId", ""),
                    "severity": _worst_severity(entry),
                    "users": users,
                    "groups": groups,
                    "roles": roles,
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
        ["provider", "policyType", "policyName", "severity", "users", "groups", "roles", "actionCount", "actions"]
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
                "; ".join(row["roles"]),
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
        if row["roles"]:
            attached.append(f"roles: {', '.join(row['roles'])}")
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
