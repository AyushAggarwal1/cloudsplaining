"""Risk constants for OCI policy analysis.

OCI authorization is expressed as human-readable *policy statements*:

    Allow group <group> to <verb> <resource-type> in <location> [where <condition>]

* **Verbs** are ordered by privilege: ``inspect`` < ``read`` < ``use`` <
  ``manage``. ``manage`` grants full CRUD including delete.
* **Resource type** can be a family (e.g. ``all-resources``,
  ``instance-family``) or a single type (``buckets``).
* **Location** is ``tenancy`` (everything) or ``compartment <name>``.
* **Subject** is usually ``group <name>`` but can be ``dynamic-group <name>``,
  ``any-user``, or ``service <name>``.

References:
* https://docs.oracle.com/en-us/iaas/Content/Identity/Concepts/policysyntax.htm
* https://docs.oracle.com/en-us/iaas/Content/Identity/Reference/policyreference.htm
"""

# Copyright (c) 2020, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
from __future__ import annotations

# Privilege ordering of verbs.
VERB_LEVELS: dict[str, int] = {
    "inspect": 1,
    "read": 2,
    "use": 3,
    "manage": 4,
}

# Subjects that broaden a statement beyond a specific group.
BROAD_SUBJECTS: set[str] = {"any-user"}

# Identity resource types: managing these is a privilege-escalation primitive,
# because the holder can change who is in groups / what policies say.
IDENTITY_RESOURCE_TYPES: set[str] = {
    "all-resources",
    "policies",
    "groups",
    "users",
    "dynamic-groups",
    "domains",
    "identity-providers",
    "compartments",
}

# Resource families that imply broad infrastructure control.
BROAD_RESOURCE_FAMILIES: set[str] = {
    "all-resources",
    "instance-family",
    "virtual-network-family",
    "volume-family",
    "object-family",
    "database-family",
}

# Resource types associated with credential / secret exposure.
CREDENTIALS_RESOURCE_TYPES: set[str] = {
    "secret-family",
    "secrets",
    "secret-bundles",
    "vaults",
    "keys",
    "auth-tokens",
    "api-keys",
}

# Resource types associated with data exfiltration when readable.
DATA_RESOURCE_TYPES: set[str] = {
    "objects",
    "object-family",
    "buckets",
    "autonomous-databases",
    "database-family",
}

# Resource types whose policies/exposure can be changed (resource exposure).
EXPOSURE_RESOURCE_TYPES: set[str] = {
    "buckets",
    "object-family",
    "load-balancers",
    "network-security-groups",
    "security-lists",
}
