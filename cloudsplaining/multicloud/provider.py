"""Abstract provider interface for multi-cloud IAM analysis."""

# Copyright (c) 2020, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from cloudsplaining.multicloud.model import AccountModel


class Provider(ABC):
    """Base class every cloud analyzer implements.

    A provider takes that cloud's native IAM snapshot (parsed JSON) and returns
    an :class:`~cloudsplaining.multicloud.model.AccountModel` — the identity +
    policy graph that :mod:`cloudsplaining.multicloud.report_aws` serializes into
    the AWS report shape.
    """

    #: Short, lowercase provider identifier, e.g. ``"azure"``.
    name: str = ""

    @abstractmethod
    def scan(self, data: Any) -> AccountModel:
        """Analyze ``data`` and return the populated account model."""
        raise NotImplementedError


def get_provider(name: str) -> Provider:
    """Return a provider instance by name (``azure``, ``gcp``, or ``oci``)."""
    # Imported lazily to avoid import cycles and to keep startup cheap.
    key = name.strip().lower()
    if key == "azure":
        from cloudsplaining.multicloud.azure.engine import AzureProvider

        return AzureProvider()
    if key == "gcp":
        from cloudsplaining.multicloud.gcp.engine import GcpProvider

        return GcpProvider()
    if key in ("oci", "oracle"):
        from cloudsplaining.multicloud.oci.engine import OciProvider

        return OciProvider()
    raise ValueError(f"Unsupported provider: {name!r}. Choose one of: azure, gcp, oci.")


SUPPORTED_PROVIDERS = ("azure", "gcp", "oci")
