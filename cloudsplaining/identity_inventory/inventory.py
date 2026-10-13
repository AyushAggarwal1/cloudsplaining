"""Provider dispatch and serialization for the identity lifecycle inventory."""

# Copyright (c) 2020, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
from __future__ import annotations

import csv
import io
from typing import TYPE_CHECKING, Any

from cloudsplaining.identity_inventory import aws, azure, gcp, oci

if TYPE_CHECKING:
    from datetime import datetime

    from cloudsplaining.identity_inventory.model import IdentityRecord

SUPPORTED_PROVIDERS = ("aws", "azure", "gcp", "oci")

_ALIASES = {"oracle": "oci"}
_BUILDERS = {
    "aws": aws.build_inventory,
    "azure": azure.build_inventory,
    "gcp": gcp.build_inventory,
    "oci": oci.build_inventory,
}


def build_identity_records(provider: str, data: dict[str, Any]) -> list[IdentityRecord]:
    """Build the inventory for ``provider`` ("oracle" aliases to "oci") from its snapshot dict."""
    key = provider.strip().lower()
    builder = _BUILDERS.get(_ALIASES.get(key, key))
    if builder is None:
        choices = ", ".join((*SUPPORTED_PROVIDERS, "oracle"))
        raise ValueError(f"Unsupported provider: {provider!r}. Choose one of: {choices}.")
    return builder(data)


def build_identity_inventory(
    provider: str,
    data: dict[str, Any],
    reference_time: datetime | None = None,
) -> list[dict[str, Any]]:
    """The inventory as serializable rows, with age/staleness derived against ``reference_time``."""
    return [record.to_dict(reference_time=reference_time) for record in build_identity_records(provider, data)]


def to_csv(rows: list[dict[str, Any]]) -> str:
    """Render inventory rows as CSV; ``None`` becomes an empty cell."""
    if not rows:
        return ""
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=list(rows[0].keys()), lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()
