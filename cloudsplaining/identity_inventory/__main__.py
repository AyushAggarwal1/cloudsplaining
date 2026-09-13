"""Run the identity inventory from the command line.

Example::

    python -m cloudsplaining.identity_inventory --provider aws \\
        --input authz-details.json --output-format csv --output identities.csv
"""

# Copyright (c) 2020, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
from __future__ import annotations

import json
from pathlib import Path

import click

from cloudsplaining.identity_inventory.inventory import (
    SUPPORTED_PROVIDERS,
    build_identity_inventory,
    to_csv,
)
from cloudsplaining.identity_inventory.parsing import parse_timestamp


@click.command("identity-inventory", short_help="Classify cloud identities as human or machine with lifecycle data.")
@click.option(
    "--provider",
    "-p",
    type=click.Choice([*SUPPORTED_PROVIDERS, "oracle"], case_sensitive=False),
    required=True,
    help="Cloud the input snapshot belongs to.",
)
@click.option(
    "--input",
    "-i",
    "input_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Identity snapshot JSON for the chosen provider.",
)
@click.option(
    "--output",
    "-o",
    "output_file",
    type=click.Path(dir_okay=False, writable=True, path_type=Path),
    default=None,
    help="Write the inventory here instead of stdout.",
)
@click.option(
    "--output-format",
    "-f",
    type=click.Choice(["json", "csv"]),
    default="json",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--reference-time",
    default=None,
    help="ISO-8601 instant to compute age_days/days_since_last_used against (default: now, UTC).",
)
def identity_inventory(
    provider: str,
    input_file: Path,
    output_file: Path | None,
    output_format: str,
    reference_time: str | None,
) -> None:
    """Inventory every identity in a cloud snapshot: human/machine classification,
    created_at, age_days, days_since_last_used, created_by, and last_used."""
    reference = parse_timestamp(reference_time)
    if reference_time and reference is None:
        raise click.BadParameter(f"not an ISO-8601 timestamp: {reference_time!r}", param_hint="--reference-time")
    data = json.loads(input_file.read_text(encoding="utf-8"))
    rows = build_identity_inventory(provider, data, reference_time=reference)
    rendered = to_csv(rows) if output_format == "csv" else json.dumps(rows, indent=2)
    if output_file:
        output_file.write_text(rendered if rendered.endswith("\n") else rendered + "\n", encoding="utf-8")
        click.echo(f"Wrote {len(rows)} identities to {output_file}", err=True)
    else:
        click.echo(rendered)


if __name__ == "__main__":
    identity_inventory()
