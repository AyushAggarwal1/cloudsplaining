"""Machine-vs-human name heuristics shared across the cloud builders.

Structural signals (identity type, trust policy, capabilities) always take
precedence in the per-cloud builders; these name heuristics only reclassify
user-shaped identities that are obviously automation accounts.
"""

# Copyright (c) 2020, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
from __future__ import annotations

import re

from cloudsplaining.identity_inventory.model import MACHINE, UNKNOWN

#: Tokens that mark a name as automation when they appear as a whole word,
#: i.e. delimited by ``-``/``_``/``.``/digits or the string edges — so
#: ``svc-deployer`` matches but ``apparna`` does not.
MACHINE_NAME_TOKENS = (
    "agent",
    "airflow",
    "ansible",
    "api",
    "app",
    "argocd",
    "automation",
    "backup",
    "batch",
    "bot",
    "build",
    "cd",
    "ci",
    "cicd",
    "ciem",
    "circleci",
    "cnapp",
    "collector",
    "cron",
    "cspm",
    "daemon",
    "deploy",
    "deployer",
    "devops",
    "ecs",
    "eks",
    "etl",
    "exporter",
    "flux",
    "function",
    "gha",
    "github",
    "gitlab",
    "grafana",
    "ingest",
    "integration",
    "jenkins",
    "job",
    "kube",
    "lambda",
    "machine",
    "monitor",
    "monitoring",
    "noreply",
    "packer",
    "pipeline",
    "prometheus",
    "robot",
    "runner",
    "scanner",
    "scheduler",
    "script",
    "service",
    "siem",
    "smtp",
    "spinnaker",
    "svc",
    "sync",
    "system",
    "task",
    "terraform",
    "worker",
)

_TOKEN_PATTERN = re.compile(r"(?:^|[-_.])(?P<token>" + "|".join(MACHINE_NAME_TOKENS) + r")(?:$|[-_.0-9])")

#: Email domains that only workloads use; a user-shaped identity with one is a machine.
MACHINE_DOMAIN_SUFFIXES = ("gserviceaccount.com",)


def is_machine_name(name: str | None) -> bool:
    """Whether ``name`` looks like an automation account rather than a person.

    For email-style names only the local part is considered, so a person at a
    company whose domain contains a token is not misclassified.
    """
    if not name:
        return False
    local_part = name.lower().split("@", 1)[0]
    return bool(_TOKEN_PATTERN.search(local_part))


def machine_name_signal(*names: str | None) -> tuple[str, str] | None:
    """A ``(MACHINE, reason)`` signal when any name looks like automation, else ``None``.

    Checks the token heuristic on the email local part, then workload email domains.
    """
    for name in names:
        if not name:
            continue
        lowered = name.lower()
        match = _TOKEN_PATTERN.search(lowered.split("@", 1)[0])
        if match:
            return (MACHINE, f"automation-style name (token: {match.group('token')})")
        domain = lowered.rsplit("@", 1)[-1] if "@" in lowered else ""
        for suffix in MACHINE_DOMAIN_SUFFIXES:
            if domain == suffix or domain.endswith("." + suffix):
                return (MACHINE, f"workload email domain ({suffix})")
    return None


def resolve(*signals: tuple[str, str] | None, fallback: str) -> tuple[str, str]:
    """First present (classification, reason) signal wins; no signals → UNKNOWN."""
    for signal in signals:
        if signal is not None:
            return signal
    return (UNKNOWN, fallback)
