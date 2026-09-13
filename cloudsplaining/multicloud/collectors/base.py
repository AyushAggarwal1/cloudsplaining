"""Collector base class and lazy-import helper."""

# Copyright (c) 2020, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
from __future__ import annotations

import importlib
from abc import ABC, abstractmethod
from types import ModuleType
from typing import Any


class CollectorDependencyError(ImportError):
    """Raised when a collector's cloud SDK is not installed."""


class Collector(ABC):
    """Authenticates to a cloud and returns a snapshot dict for its engine."""

    #: Short, lowercase provider identifier.
    name: str = ""
    #: The pip extra that installs this collector's dependencies.
    extra: str = ""

    @abstractmethod
    def collect(self) -> dict[str, Any]:
        """Return the snapshot dict consumed by the matching engine."""
        raise NotImplementedError

    def _import(self, module: str) -> ModuleType:
        """Import ``module`` or raise an actionable error naming the pip extra."""
        try:
            return importlib.import_module(module)
        except ImportError as error:  # pragma: no cover - exercised via tests with monkeypatch
            raise CollectorDependencyError(
                f"The '{self.name}' collector requires the '{module}' package. "
                f"Install it with: pip install 'cloudsplaining[{self.extra}]'"
            ) from error
