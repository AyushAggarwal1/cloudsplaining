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
    "circleci",
    "cron",
    "daemon",
    "deploy",
    "deployer",
    "ecs",
    "eks",
    "etl",
    "flux",
    "function",
    "gha",
    "github",
    "gitlab",
    "grafana",
    "integration",
    "jenkins",
    "job",
    "kube",
    "lambda",
    "machine",
    "monitor",
    "monitoring",
    "packer",
    "pipeline",
    "prometheus",
    "robot",
    "runner",
    "scanner",
    "scheduler",
    "script",
    "service",
    "spinnaker",
    "svc",
    "sync",
    "system",
    "task",
    "terraform",
    "worker",
)

_TOKEN_PATTERN = re.compile(r"(?:^|[-_.])(?:" + "|".join(MACHINE_NAME_TOKENS) + r")(?:$|[-_.0-9])")


def is_machine_name(name: str | None) -> bool:
    """Whether ``name`` looks like an automation account rather than a person.

    For email-style names only the local part is considered, so a person at a
    company whose domain contains a token is not misclassified.
    """
    if not name:
        return False
    local_part = name.lower().split("@", 1)[0]
    return bool(_TOKEN_PATTERN.search(local_part))
