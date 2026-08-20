"""Scan Azure, GCP, or OCI IAM exports for least-privilege violations.

This is the multi-cloud counterpart to the AWS ``scan`` command. Each provider
ingests that cloud's native IAM export and emits normalized findings.
"""

# Copyright (c) 2020, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any

import click

from cloudsplaining import set_log_level
from cloudsplaining.identity_inventory.inventory import build_identity_inventory
from cloudsplaining.multicloud import get_provider
from cloudsplaining.multicloud.analysis import CATEGORY_ORDER
from cloudsplaining.multicloud.provider import SUPPORTED_PROVIDERS
from cloudsplaining.multicloud.report import render_console, render_html
from cloudsplaining.multicloud.serialize import permission_collection_key, render

logger = logging.getLogger(__name__)


@click.command(
    name="scan-cloud",
    short_help="Scan an Azure, GCP, or OCI IAM export for least-privilege violations.",
)
@click.option(
    "-p",
    "--provider",
    "provider_name",
    type=click.Choice(SUPPORTED_PROVIDERS, case_sensitive=False),
    required=True,
    help="The cloud provider whose IAM export you are scanning.",
)
@click.option(
    "-i",
    "--input-file",
    type=click.Path(exists=True),
    required=False,
    help="Path to the IAM export. If omitted, input is read from STDIN.",
)
@click.option(
    "-o",
    "--output",
    "output_format",
    type=click.Choice(["console", "json", "html"], case_sensitive=False),
    default="console",
    help="Output format.",
)
@click.option(
    "--output-file",
    type=str,
    required=False,
    help="Write the output to this file instead of STDOUT.",
)
@click.option(
    "-f",
    "--filter-severity",
    "severity",
    help="Only report findings at or matching these severities.",
    multiple=True,
    type=click.Choice(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], case_sensitive=False),
)
@click.option("--verbose", "-v", "verbosity", count=True)
def scan_cloud(
    provider_name: str,
    input_file: str | None,
    output_format: str,
    output_file: str | None,
    severity: tuple[str, ...],
    verbosity: int,
) -> None:
    """Scan an Azure, GCP, or OCI IAM export for least-privilege violations."""
    set_log_level(verbosity)

    raw = _read_input(input_file)
    data = _load_data(raw, provider_name)

    provider = get_provider(provider_name)
    model = provider.scan(data)

    # Build the full report, then optionally prune category findings below the
    # requested severities.
    report = render(model)
    if isinstance(data, dict):
        # The snapshot doubles as the identity-lifecycle source; statement-list
        # inputs (OCI paste mode) carry no identities to inventory.
        report["identity_inventory"] = build_identity_inventory(provider_name, data)
    wanted = {s.lower() for s in severity}
    if wanted:
        _filter_severities(report, wanted)

    if output_format == "json":
        rendered = json.dumps(report, indent=2, default=str)
    elif output_format == "html":
        rendered = render_html(report)
    else:
        rendered = render_console(report, use_color=not output_file)

    if output_file:
        Path(output_file).write_text(rendered, encoding="utf-8")
        print(f"Wrote {provider_name} IAM report to {output_file}")
    else:
        print(rendered)

    # Exit non-zero if any critical/high finding is present, so the command is
    # usable as a CI gate.
    if _has_severity(report, {"critical", "high"}):
        sys.exit(1)


def _filter_severities(report: dict[str, Any], wanted: set[str]) -> None:
    """Drop category findings whose severity is not in ``wanted`` (in place)."""
    collection = permission_collection_key(report.get("provider", ""))
    for entry in report.get(collection, {}).values():
        for category in CATEGORY_ORDER:
            block = entry.get(category)
            if block and block.get("severity") not in wanted:
                block["findings"] = []
                block["severity"] = "none"


def _has_severity(report: dict[str, Any], wanted: set[str]) -> bool:
    collection = permission_collection_key(report.get("provider", ""))
    for entry in report.get(collection, {}).values():
        for category in CATEGORY_ORDER:
            block = entry.get(category) or {}
            if block.get("findings") and block.get("severity") in wanted:
                return True
    return False


def _read_input(input_file: str | None) -> str:
    if input_file:
        return Path(input_file).read_text(encoding="utf-8")
    return sys.stdin.read()


def _load_data(raw: str, provider_name: str) -> Any:
    """Parse the raw input into the structure the provider expects.

    JSON is always attempted first. For OCI, a non-JSON payload is treated as a
    newline-delimited list of policy statements, which is a common way to paste
    OCI policies.
    """
    raw = raw.strip()
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        if provider_name.lower() in ("oci", "oracle"):
            return [line.strip() for line in raw.splitlines() if line.strip()]
        logger.critical("Input is not valid JSON.")
        sys.exit(1)
