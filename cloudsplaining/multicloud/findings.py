"""Normalized finding model shared across all multi-cloud providers."""

# Copyright (c) 2020, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    """Severity ranking shared by all providers.

    Implemented as an ``IntEnum`` so findings sort highest-risk-first naturally.
    The names line up with the severities the AWS report already uses.
    """

    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0

    @classmethod
    def from_name(cls, name: str) -> Severity:
        try:
            return cls[name.strip().upper()]
        except KeyError as error:
            raise ValueError(f"Unknown severity: {name!r}") from error


# Finding type categories. These intentionally mirror the AWS risk categories
# (where they apply) so a reader familiar with the AWS report understands them,
# while adding categories that only make sense for the other clouds.
PRIVILEGE_ESCALATION = "PrivilegeEscalation"
RESOURCE_EXPOSURE = "ResourceExposure"
DATA_EXFILTRATION = "DataExfiltration"
CREDENTIALS_EXPOSURE = "CredentialsExposure"
INFRASTRUCTURE_MODIFICATION = "InfrastructureModification"
PUBLIC_ACCESS = "PublicAccess"
SERVICE_WILDCARD = "ServiceWildcard"
OVERLY_BROAD_SCOPE = "OverlyBroadScope"


@dataclass
class Finding:
    """A single normalized least-privilege finding.

    Every provider maps its native concepts onto these fields so downstream
    rendering does not need to know which cloud produced the finding.
    """

    provider: str
    finding_type: str
    severity: Severity
    principal: str
    """The grant holder: an Azure role/assignment, a GCP role/member, an OCI group."""
    scope: str
    """Where the grant applies: subscription/resource scope, project, compartment/tenancy."""
    permissions: list[str]
    """The risky permissions/actions that triggered the finding."""
    title: str
    description: str
    recommendation: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def json(self) -> dict[str, Any]:
        """Return a JSON-serializable representation."""
        return {
            "provider": self.provider,
            "findingType": self.finding_type,
            "severity": self.severity.name,
            "principal": self.principal,
            "scope": self.scope,
            "permissions": self.permissions,
            "title": self.title,
            "description": self.description,
            "recommendation": self.recommendation,
            "metadata": self.metadata,
        }


class FindingsResult:
    """An ordered, filterable collection of :class:`Finding` objects."""

    def __init__(self, provider: str, findings: list[Finding] | None = None) -> None:
        self.provider = provider
        self.findings: list[Finding] = findings or []

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def extend(self, findings: list[Finding]) -> None:
        self.findings.extend(findings)

    def filter_severity(self, severities: list[str] | None) -> list[Finding]:
        """Return findings whose severity is in ``severities`` (case-insensitive).

        ``None`` or empty returns everything.
        """
        if not severities:
            return self.sorted()
        wanted = {Severity.from_name(s) for s in severities}
        return [f for f in self.sorted() if f.severity in wanted]

    def sorted(self) -> list[Finding]:
        """Highest severity first, then by principal for stable output."""
        return sorted(self.findings, key=lambda f: (-int(f.severity), f.principal, f.title))

    def counts_by_severity(self) -> dict[str, int]:
        counts = {sev.name: 0 for sev in Severity}
        for finding in self.findings:
            counts[finding.severity.name] += 1
        return counts

    def json(self, severities: list[str] | None = None) -> dict[str, Any]:
        selected = self.filter_severity(severities)
        return {
            "provider": self.provider,
            "summary": {
                "total": len(selected),
                "bySeverity": _counts(selected),
            },
            "findings": [f.json() for f in selected],
        }

    def __len__(self) -> int:
        return len(self.findings)

    def __iter__(self) -> Any:
        return iter(self.sorted())


def _counts(findings: list[Finding]) -> dict[str, int]:
    counts = {sev.name: 0 for sev in Severity}
    for finding in findings:
        counts[finding.severity.name] += 1
    return counts


def dump_json(result: FindingsResult, severities: list[str] | None = None, indent: int = 2) -> str:
    return json.dumps(result.json(severities), indent=indent, default=str)
