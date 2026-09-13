"""Multi-cloud IAM least-privilege analysis for Cloudsplaining.

This package extends Cloudsplaining beyond AWS to Azure, GCP, and Oracle Cloud
Infrastructure (OCI). Each cloud uses a fundamentally different authorization
model, so rather than forcing the AWS ``Effect``/``Action``/``Resource`` grammar
onto them, every provider implements a small :class:`~cloudsplaining.multicloud.provider.Provider`
interface that ingests that cloud's native IAM export and emits a normalized list
of :class:`~cloudsplaining.multicloud.findings.Finding` objects.

The normalized findings can then be rendered consistently (console, JSON, HTML)
regardless of which cloud produced them.
"""

# Copyright (c) 2020, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
from __future__ import annotations

from cloudsplaining.multicloud.findings import Finding, FindingsResult, Severity
from cloudsplaining.multicloud.provider import Provider, get_provider

__all__ = [
    "Finding",
    "FindingsResult",
    "Severity",
    "Provider",
    "get_provider",
]
