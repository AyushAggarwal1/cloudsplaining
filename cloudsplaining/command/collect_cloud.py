"""Collect an Azure, GCP, or OCI IAM snapshot using the cloud SDKs.

The snapshot is the input to ``scan-cloud``. This mirrors the AWS ``download``
command, which runs ``get-account-authorization-details`` and stores the result.
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

import click

from cloudsplaining import set_log_level
from cloudsplaining.multicloud.collectors import get_collector
from cloudsplaining.multicloud.collectors.base import CollectorDependencyError
from cloudsplaining.multicloud.provider import SUPPORTED_PROVIDERS

logger = logging.getLogger(__name__)


@click.command(
    name="collect-cloud",
    short_help="Collect an Azure, GCP, or OCI IAM snapshot for use with scan-cloud.",
)
@click.option(
    "-p",
    "--provider",
    "provider_name",
    type=click.Choice(SUPPORTED_PROVIDERS, case_sensitive=False),
    required=True,
    help="The cloud provider to collect from.",
)
@click.option(
    "--subscription-id",
    help="[azure] Azure subscription ID to scope role definitions/assignments to.",
)
@click.option("--project-id", help="[gcp] GCP project ID to collect IAM data from.")
@click.option("--tenancy-id", help="[oci] OCI tenancy OCID (defaults to the config file's tenancy).")
@click.option("--config-profile", default="DEFAULT", help="[oci] OCI config profile name.")
@click.option(
    "-o",
    "--output-file",
    type=str,
    required=False,
    help="Write the snapshot here. Defaults to <provider>-snapshot.json.",
)
@click.option("--verbose", "-v", "verbosity", count=True)
def collect_cloud(
    provider_name: str,
    subscription_id: str | None,
    project_id: str | None,
    tenancy_id: str | None,
    config_profile: str,
    output_file: str | None,
    verbosity: int,
) -> None:
    """Collect an Azure, GCP, or OCI IAM snapshot for use with scan-cloud."""
    set_log_level(verbosity)

    options = {
        "subscription_id": subscription_id,
        "project_id": project_id,
        "tenancy_id": tenancy_id,
        "config_profile": config_profile,
    }
    try:
        collector = get_collector(provider_name, **options)
        snapshot = collector.collect()
    except CollectorDependencyError as error:
        logger.critical(str(error))
        sys.exit(1)
    except ValueError as error:
        logger.critical(str(error))
        sys.exit(1)

    destination = output_file or f"{provider_name.lower()}-snapshot.json"
    Path(destination).write_text(json.dumps(snapshot, indent=2, default=str), encoding="utf-8")
    print(f"Wrote {provider_name} IAM snapshot to {destination}")
    print(f"Next: cloudsplaining scan-cloud -p {provider_name} -i {destination} -o html --output-file report.html")
