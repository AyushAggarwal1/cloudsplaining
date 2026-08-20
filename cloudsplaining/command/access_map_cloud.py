"""Produce a policy -> principals -> actions access map from a scan-cloud report."""

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

import click

from cloudsplaining import set_log_level
from cloudsplaining.multicloud import access_map
from cloudsplaining.multicloud.serialize import permission_collection_key

logger = logging.getLogger(__name__)


@click.command(
    name="access-map",
    short_help="From a scan-cloud report, list each policy, who it is attached to, and the actions it grants.",
)
@click.option(
    "-i",
    "--input-file",
    type=click.Path(exists=True),
    required=True,
    help="A JSON report produced by `scan-cloud ... -o json`.",
)
@click.option(
    "-o",
    "--output",
    "output_format",
    type=click.Choice(["console", "json", "csv"], case_sensitive=False),
    default="console",
    help="Output format.",
)
@click.option("--output-file", type=str, required=False, help="Write the output to this file instead of STDOUT.")
@click.option(
    "--only-attached",
    is_flag=True,
    default=False,
    help="Only include policies that are attached to at least one user, group, or role.",
)
@click.option("--verbose", "-v", "verbosity", count=True)
def access_map_cloud(
    input_file: str,
    output_format: str,
    output_file: str | None,
    only_attached: bool,
    verbosity: int,
) -> None:
    """List each policy, who it is attached to (users/groups/roles), and the actions it grants."""
    set_log_level(verbosity)

    report = json.loads(Path(input_file).read_text(encoding="utf-8"))
    if permission_collection_key(report.get("provider", "")) not in report:
        logger.critical("Input does not look like a scan-cloud JSON report (no permission-set collection found).")
        sys.exit(1)

    rows = access_map.build(report, only_attached=only_attached)

    if output_format == "json":
        rendered = access_map.render_json(rows)
    elif output_format == "csv":
        rendered = access_map.render_csv(rows)
    else:
        rendered = access_map.render_console(rows)

    if output_file:
        Path(output_file).write_text(rendered, encoding="utf-8")
        print(f"Wrote access map for {len(rows)} policies to {output_file}")
    else:
        print(rendered)
