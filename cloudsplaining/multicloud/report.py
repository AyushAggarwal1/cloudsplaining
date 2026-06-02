"""Render the AWS-shaped multi-cloud report dict to the console or HTML.

Both renderers consume the dict produced by
:func:`cloudsplaining.multicloud.report_aws.render` (the same structure as the
AWS ``iam-findings-default.json``).
"""

# Copyright (c) 2020, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
from __future__ import annotations

import html
from typing import Any

from cloudsplaining.multicloud.analysis import CATEGORY_ORDER
from cloudsplaining.multicloud.report_aws import policy_collection_keys

_COLORS = {
    "critical": "\033[1;35m",
    "high": "\033[1;31m",
    "medium": "\033[1;33m",
    "low": "\033[1;36m",
    "info": "\033[0;37m",
    "none": "",
}
_RESET = "\033[0;0m"
_RANK = {"none": 0, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

_HTML_BADGE = {
    "critical": "#7b1fa2",
    "high": "#c62828",
    "medium": "#ef6c00",
    "low": "#0277bd",
    "info": "#546e7a",
    "none": "#9e9e9e",
}

_IDENTITY_COLLECTIONS = ("users", "groups", "roles")


def _policy_severity(entry: dict[str, Any]) -> str:
    worst = "none"
    for category in CATEGORY_ORDER:
        block = entry.get(category) or {}
        if block.get("findings") and _RANK.get(block.get("severity", "none"), 0) > _RANK[worst]:
            worst = block["severity"]
    return worst


def _flagged_policies(report: dict[str, Any]) -> list[tuple[str, str, dict[str, Any]]]:
    """Return (collection, policy_id, entry) for every policy that has findings."""
    out = []
    for collection in policy_collection_keys(report):
        for pid, entry in report.get(collection, {}).items():
            if any((entry.get(cat) or {}).get("findings") for cat in CATEGORY_ORDER):
                out.append((collection, pid, entry))
    out.sort(key=lambda t: -_RANK.get(_policy_severity(t[2]), 0))
    return out


def render_console(report: dict[str, Any], use_color: bool = True) -> str:
    provider = report.get("provider", "?").upper()
    lines: list[str] = []
    title = f"Cloudsplaining {provider} IAM assessment"
    lines.append(title)
    lines.append("=" * len(title))

    collections = (*_IDENTITY_COLLECTIONS, *policy_collection_keys(report))
    counts = {k: len(report.get(k, {})) for k in collections}
    lines.append(
        "Inventory: " + ", ".join(f"{counts[k]} {k.replace('_', ' ')}" for k in collections if counts[k])
    )

    flagged = _flagged_policies(report)
    if not flagged:
        lines.append("\nNo policy findings.")
        return "\n".join(lines)

    sev_counts: dict[str, int] = {}
    for _, _, entry in flagged:
        sev = _policy_severity(entry)
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
    lines.append(
        "Findings: "
        + "  ".join(
            f"{_c(sev, use_color)}{sev.upper()}: {sev_counts[sev]}{_r(use_color)}"
            for sev in ("critical", "high", "medium", "low")
            if sev_counts.get(sev)
        )
    )
    lines.append("")

    for collection, _pid, entry in flagged:
        sev = _policy_severity(entry)
        name = entry.get("PolicyName", "?")
        lines.append(f"{_c(sev, use_color)}[{sev.upper()}] {name}{_r(use_color)}  ({collection})")
        attached = entry.get("AttachedTo", {})
        att = ", ".join(f"{k}={len(v)}" for k, v in attached.items() if v) or "unattached"
        lines.append(f"  AttachedTo : {att}")
        for category in CATEGORY_ORDER:
            block = entry.get(category) or {}
            findings = block.get("findings")
            if not findings:
                continue
            rendered = _format_findings(findings)
            lines.append(f"  {category} [{block.get('severity')}]: {rendered}")
        lines.append("")

    return "\n".join(lines)


def _format_findings(findings: list[Any]) -> str:
    parts: list[str] = []
    for item in findings[:8]:
        if isinstance(item, dict):
            parts.append(f"{item.get('type')} ({', '.join(item.get('actions', []))})")
        else:
            parts.append(str(item))
    suffix = f", ... (+{len(findings) - 8} more)" if len(findings) > 8 else ""
    return ", ".join(parts) + suffix


def render_html(report: dict[str, Any]) -> str:
    provider = html.escape(report.get("provider", "?").upper())
    flagged = _flagged_policies(report)

    sev_counts: dict[str, int] = {}
    for _, _, entry in flagged:
        sev = _policy_severity(entry)
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    cards = "".join(
        f'<div class="card {sev}"><span class="num">{sev_counts.get(sev, 0)}</span>'
        f'<span class="lbl">{sev}</span></div>'
        for sev in ("critical", "high", "medium", "low")
    )
    inv = "".join(
        f'<div class="card"><span class="num">{len(report.get(k, {}))}</span>'
        f'<span class="lbl">{k.replace("_", " ")}</span></div>'
        for k in (*_IDENTITY_COLLECTIONS, *policy_collection_keys(report))
    )
    rows = "\n".join(_html_row(c, e) for c, _pid, e in flagged) or (
        '<tr><td colspan="5">No policy findings.</td></tr>'
    )

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cloudsplaining {provider} IAM Report</title>
<style>
 body {{ font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; margin:0;
        background:#f4f6f8; color:#1f2933; }}
 header {{ background:#1f2933; color:#fff; padding:24px 32px; }}
 header h1 {{ margin:0; font-size:20px; }}
 .cards {{ display:flex; gap:12px; padding:20px 32px; flex-wrap:wrap; }}
 .card {{ background:#fff; border-radius:8px; padding:14px 18px; min-width:84px;
         box-shadow:0 1px 3px rgba(0,0,0,.1); display:flex; flex-direction:column; }}
 .card .num {{ font-size:26px; font-weight:700; }}
 .card .lbl {{ font-size:11px; letter-spacing:.06em; text-transform:uppercase; opacity:.6; }}
 .card.critical .num {{ color:#7b1fa2; }} .card.high .num {{ color:#c62828; }}
 .card.medium .num {{ color:#ef6c00; }} .card.low .num {{ color:#0277bd; }}
 table {{ width:calc(100% - 64px); margin:0 32px 40px; border-collapse:collapse; background:#fff;
         border-radius:8px; overflow:hidden; box-shadow:0 1px 3px rgba(0,0,0,.1); }}
 th,td {{ text-align:left; padding:10px 14px; font-size:13px; vertical-align:top; border-bottom:1px solid #eceff1; }}
 th {{ background:#eceff1; text-transform:uppercase; font-size:11px; letter-spacing:.05em; }}
 .badge {{ color:#fff; padding:2px 8px; border-radius:10px; font-size:11px; font-weight:700; }}
 code {{ background:#f4f6f8; padding:1px 4px; border-radius:3px; font-size:12px; }}
</style></head>
<body>
<header><h1>Cloudsplaining &middot; {provider} IAM Least-Privilege Report</h1></header>
<div class="cards">{cards}</div>
<div class="cards">{inv}</div>
<table>
 <thead><tr><th>Severity</th><th>Policy</th><th>Type</th><th>Attached To</th><th>Findings</th></tr></thead>
 <tbody>
{rows}
 </tbody>
</table>
</body></html>
"""


def _html_row(collection: str, entry: dict[str, Any]) -> str:
    sev = _policy_severity(entry)
    color = _HTML_BADGE.get(sev, "#9e9e9e")
    name = html.escape(str(entry.get("PolicyName", "?")))
    attached = entry.get("AttachedTo", {})
    att = html.escape(", ".join(f"{k}: {', '.join(v)}" for k, v in attached.items() if v) or "unattached")
    detail_parts = []
    for category in CATEGORY_ORDER:
        block = entry.get(category) or {}
        if block.get("findings"):
            detail_parts.append(
                f"<strong>{category}</strong> ({html.escape(block.get('severity', ''))}): "
                f"<code>{html.escape(_format_findings(block['findings']))}</code>"
            )
    detail = "<br>".join(detail_parts)
    return (
        f"<tr><td><span class='badge' style='background:{color}'>{sev.upper()}</span></td>"
        f"<td>{name}</td><td>{html.escape(collection)}</td><td>{att}</td><td>{detail}</td></tr>"
    )


def _c(severity: str, use_color: bool) -> str:
    return _COLORS.get(severity, "") if use_color else ""


def _r(use_color: bool) -> str:
    return _RESET if use_color else ""
