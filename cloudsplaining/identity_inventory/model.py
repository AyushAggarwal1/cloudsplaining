"""Normalized identity lifecycle record shared by every cloud builder."""

# Copyright (c) 2020, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from cloudsplaining.identity_inventory.parsing import days_since, parse_timestamp, utc_now

if TYPE_CHECKING:
    from datetime import datetime

HUMAN = "human"
MACHINE = "machine"
UNKNOWN = "unknown"


@dataclass
class IdentityRecord:
    """One cloud identity (human or machine) with its lifecycle facts.

    ``age_days`` and ``days_since_last_used`` are not stored: they depend on the
    moment of observation and are derived in :meth:`to_dict`.
    """

    provider: str  # aws | azure | gcp | oci
    identity_type: str  # user | role | access_key | service_principal | service_account | dynamic_group
    id: str
    name: str
    classification: str  # HUMAN | MACHINE | UNKNOWN
    classification_reason: str | None = None
    created_at: datetime | None = None
    last_used: datetime | None = None
    created_by: str | None = None

    def to_dict(self, reference_time: datetime | None = None) -> dict[str, Any]:
        """Serialize with derived fields computed against ``reference_time`` (default: now, UTC)."""
        reference = parse_timestamp(reference_time) or utc_now()
        created_at = parse_timestamp(self.created_at)
        last_used = parse_timestamp(self.last_used)
        return {
            "provider": self.provider,
            "identity_type": self.identity_type,
            "id": self.id,
            "name": self.name,
            "classification": self.classification,
            "classification_reason": self.classification_reason,
            "created_at": created_at.isoformat() if created_at else None,
            "age_days": days_since(created_at, reference),
            "days_since_last_used": days_since(last_used, reference),
            "created_by": self.created_by,
            "last_used": last_used.isoformat() if last_used else None,
        }
