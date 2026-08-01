"""Tolerant parsing helpers shared by the per-cloud identity inventory builders."""

# Copyright (c) 2020, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
from __future__ import annotations

import re
from datetime import date, datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Mapping

#: Placeholder strings cloud exports use for "no data" (the last three appear in
#: AWS credential reports).
_NULL_SENTINELS = frozenset({"", "null", "none", "n/a", "no_information", "not_supported"})

_CAMEL_BOUNDARY = re.compile(r"([a-z0-9])([A-Z])")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_timestamp(value: object) -> datetime | None:
    """Parse an ISO-8601-ish export value into an aware UTC datetime, else ``None``.

    Naive datetimes are assumed UTC; sentinel strings and garbage return ``None``.
    """
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day, tzinfo=timezone.utc)
    if not isinstance(value, str) or value.strip().lower() in _NULL_SENTINELS:
        return None
    text = value.strip()
    # datetime.fromisoformat only accepts the "Z" suffix from Python 3.11 on.
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def max_timestamp(*values: object) -> datetime | None:
    """The latest parseable timestamp among ``values``, else ``None``."""
    stamps = [stamp for stamp in map(parse_timestamp, values) if stamp is not None]
    return max(stamps) if stamps else None


def days_since(value: datetime | None, reference_time: datetime) -> int | None:
    """Whole days from ``value`` to ``reference_time`` (clamped at 0), or ``None``."""
    if value is None:
        return None
    return max((reference_time - value).days, 0)


def as_bool(value: object) -> bool:
    """True for boolean ``True`` or the string ``"true"`` (any case); False otherwise.

    Cloud exports disagree on flag encoding: credential reports say ``"true"``/``"false"``,
    SDK/CLI JSON uses real booleans.
    """
    if isinstance(value, bool):
        return value
    return isinstance(value, str) and value.strip().lower() == "true"


def get_field(data: Mapping[str, Any], *names: str) -> Any:  # noqa: ANN401 - JSON export values are dynamic
    """Return the first present value among each name's camelCase/kebab-case/snake_case spellings.

    Cloud exports disagree on casing: REST APIs emit camelCase, the OCI CLI kebab-case,
    and SDK serializations snake_case.
    """
    for name in names:
        words = _CAMEL_BOUNDARY.sub(r"\1 \2", name).lower().split()
        for key in (name, "-".join(words), "_".join(words)):
            if key in data:
                return data[key]
    return None
