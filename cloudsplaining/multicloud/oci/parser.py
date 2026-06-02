"""Parser for OCI natural-language policy statements.

Kept separate from the engine so both the engine (attachment/subject extraction)
and :mod:`cloudsplaining.multicloud.analysis` (risk evaluation) can reuse it.
"""

# Copyright (c) 2020, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
from __future__ import annotations

import re
from dataclasses import dataclass

from cloudsplaining.multicloud.oci import constants as c

# Allow <subject> to <verb> <resource> in <location> [where <condition>]
STATEMENT_RE = re.compile(
    r"""^\s*allow\s+
        (?P<subject_type>group|dynamic-group|service|any-user)\s*
        (?P<subject>[^\n]*?)\s+
        to\s+(?P<verb>inspect|read|use|manage)\s+
        (?P<resource>[\w-]+)\s+
        in\s+(?P<location>tenancy|compartment\s+[\w:.\-/]+)
        (?:\s+where\s+(?P<condition>.+?))?\s*$""",
    re.IGNORECASE | re.VERBOSE,
)


@dataclass
class ParsedStatement:
    raw: str
    subject_type: str
    subject: str
    verb: str
    resource: str
    location: str
    condition: str | None
    policy_name: str

    @property
    def verb_level(self) -> int:
        return c.VERB_LEVELS.get(self.verb, 0)

    @property
    def is_tenancy(self) -> bool:
        return self.location.lower().strip() == "tenancy"

    @property
    def principal(self) -> str:
        if self.subject_type == "any-user":
            return "any-user"
        label = self.subject.strip() or "?"
        return f"{self.subject_type} {label}"


def parse_statement(raw: str, policy_name: str = "<inline>") -> ParsedStatement | None:
    match = STATEMENT_RE.match(raw)
    if not match:
        return None
    g = match.groupdict()
    return ParsedStatement(
        raw=raw,
        subject_type=g["subject_type"].lower(),
        subject=g.get("subject") or "",
        verb=g["verb"].lower(),
        resource=g["resource"].lower(),
        location=g["location"].strip(),
        condition=(g.get("condition") or "").strip() or None,
        policy_name=policy_name,
    )
