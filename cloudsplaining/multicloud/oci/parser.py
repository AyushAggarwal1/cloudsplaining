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

#: Identity domain an unqualified group / dynamic-group name belongs to.
DEFAULT_DOMAIN = "Default"

#: Subject types whose names are scoped to an identity domain.
DOMAIN_SCOPED_SUBJECTS = frozenset({"group", "dynamic-group"})

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

# ``group id <ocid>`` / ``dynamic-group id <ocid>``: a reference by OCID rather than name.
SUBJECT_ID_RE = re.compile(r"^id\s+(?P<id>\S+)$", re.IGNORECASE)


@dataclass(frozen=True)
class SubjectRef:
    """A statement subject resolved to how principals are keyed.

    ``name`` is the ``<domain>/<name>`` form (see :func:`qualified_name`) or the
    bare name for subjects that are not domain-scoped (services); ``id`` is the
    OCID of an ``id <ocid>`` subject. ``any-user`` sets neither.
    """

    name: str | None = None
    id: str | None = None


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

    @property
    def subject_ref(self) -> SubjectRef:
        """The subject as a principal reference; group / dynamic-group names are domain-qualified."""
        if self.subject_type in DOMAIN_SCOPED_SUBJECTS:
            return parse_subject(self.subject)
        return SubjectRef(name=self.subject.strip() or None)


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


def parse_subject(raw: str) -> SubjectRef:
    """Resolve a group / dynamic-group subject to an OCID or a domain-qualified name."""
    match = SUBJECT_ID_RE.match(raw.strip())
    if match:
        return SubjectRef(id=match.group("id"))
    return SubjectRef(name=qualified_name(raw))


def qualified_name(name: str, domain: str | None = None) -> str:
    """Return the ``<domain>/<name>`` form of a group or dynamic-group name.

    A policy may reference the same group as ``Admins``, ``Default/Admins`` or
    ``'Default'/'Admins'`` (the syntax the console emits once identity domains
    are enabled), so every principal is keyed by this single form. A bare name
    belongs to ``domain`` when given (an identity listed from a specific domain),
    otherwise to the Default domain, which is what OCI itself assumes.
    """
    head, sep, tail = name.strip().partition("/")
    if sep:
        return f"{_unquote(head)}/{_unquote(tail)}"
    return f"{(domain or '').strip() or DEFAULT_DOMAIN}/{_unquote(head)}"


def _unquote(segment: str) -> str:
    segment = segment.strip()
    if len(segment) >= 2 and segment[0] == segment[-1] and segment[0] in "'\"":
        return segment[1:-1]
    return segment
