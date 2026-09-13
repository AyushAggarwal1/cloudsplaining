"""Cross-cloud identity lifecycle inventory.

Classifies every AWS / Azure / GCP / OCI identity as human or machine and
reports when it was created, by whom, when it was last used, and the derived
``age_days`` / ``days_since_last_used``. Builders parse offline snapshot
exports; nothing here calls cloud APIs.
"""

# Copyright (c) 2020, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
from cloudsplaining.identity_inventory.inventory import (
    SUPPORTED_PROVIDERS,
    build_identity_inventory,
    build_identity_records,
    to_csv,
)
from cloudsplaining.identity_inventory.model import HUMAN, MACHINE, IdentityRecord

__all__ = [
    "HUMAN",
    "MACHINE",
    "SUPPORTED_PROVIDERS",
    "IdentityRecord",
    "build_identity_inventory",
    "build_identity_records",
    "to_csv",
]
