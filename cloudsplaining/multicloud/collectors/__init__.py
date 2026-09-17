"""Live IAM-data collectors for the multi-cloud providers.

Each collector authenticates to its cloud and returns a *snapshot* dict in the
shape the corresponding engine consumes. SDKs are imported lazily so the base
package has no hard dependency on any cloud SDK; install the relevant extra
(``pip install cloudsplaining[azure|gcp|oci]``) to use a collector.
"""

# Copyright (c) 2020, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
from __future__ import annotations

from typing import Any

from cloudsplaining.multicloud.collectors.base import Collector


def get_collector(provider: str, **options: Any) -> Collector:
    """Return a collector instance for ``provider`` (``azure``, ``gcp``, ``oci``)."""
    key = provider.strip().lower()
    if key == "azure":
        from cloudsplaining.multicloud.collectors.azure import AzureCollector

        return AzureCollector(**options)
    if key == "gcp":
        from cloudsplaining.multicloud.collectors.gcp import GcpCollector

        return GcpCollector(**options)
    if key in ("oci", "oracle"):
        from cloudsplaining.multicloud.collectors.oci import OciCollector

        return OciCollector(**options)
    raise ValueError(f"Unsupported provider: {provider!r}. Choose one of: azure, gcp, oci.")


__all__ = ["Collector", "get_collector"]
