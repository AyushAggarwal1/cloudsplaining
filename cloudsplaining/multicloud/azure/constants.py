"""Risk constants for Azure RBAC analysis.

Azure RBAC role definitions express permissions as ``Actions`` / ``NotActions``
(management plane) and ``DataActions`` / ``NotDataActions`` (data plane), scoped
by ``AssignableScopes``. Action strings look like
``Microsoft.Authorization/roleAssignments/write`` and support ``*`` wildcards at
any segment.

References:
* https://learn.microsoft.com/azure/role-based-access-control/role-definitions
* https://learn.microsoft.com/azure/role-based-access-control/built-in-roles
"""

# Copyright (c) 2020, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
from __future__ import annotations

# Built-in roles that grant broad or privilege-escalating access. The IDs are
# the well-known Azure role definition GUIDs (stable across tenants).
PRIVILEGED_BUILTIN_ROLES: dict[str, str] = {
    "Owner": "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
    "Contributor": "b24988ac-6180-42a0-ab88-20f7382dd24c",
    "User Access Administrator": "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",
    "Role Based Access Control Administrator": "f58310d9-a9f6-439a-9e8d-f62e7b41a168",
}

# Role assignment / RBAC management actions = privilege escalation: whoever can
# write role assignments or definitions can grant themselves anything.
PRIVILEGE_ESCALATION_ACTIONS: set[str] = {
    "microsoft.authorization/roleassignments/write",
    "microsoft.authorization/roledefinitions/write",
    "microsoft.authorization/elevateaccess/action",
    "microsoft.authorization/classicadministrators/write",
}

# Wildcards that, if they appear in Actions, cover the RBAC management surface
# and therefore also imply privilege escalation.
PRIVILEGE_ESCALATION_WILDCARDS: tuple[str, ...] = (
    "microsoft.authorization/*",
    "microsoft.authorization/*/write",
    "microsoft.authorization/roleassignments/*",
    "microsoft.authorization/roledefinitions/*",
)

# Actions that expose secrets / credentials (read access to the data behind
# key vaults, storage keys, etc.).
CREDENTIALS_EXPOSURE_ACTIONS: set[str] = {
    "microsoft.keyvault/vaults/secrets/read",
    "microsoft.keyvault/vaults/secrets/getsecret/action",
    "microsoft.storage/storageaccounts/listkeys/action",
    "microsoft.storage/storageaccounts/regeneratekey/action",
    "microsoft.web/sites/config/list/action",
    "microsoft.compute/virtualmachines/runcommand/action",
}

# Data-plane actions associated with bulk data read (exfiltration).
DATA_EXFILTRATION_DATA_ACTIONS: set[str] = {
    "microsoft.storage/storageaccounts/blobservices/containers/blobs/read",
    "microsoft.keyvault/vaults/secrets/getsecret/action",
    "microsoft.documentdb/databaseaccounts/sqldatabases/containers/items/read",
}

# Actions that let the holder expose resources publicly / change resource access
# policies (resource exposure).
RESOURCE_EXPOSURE_ACTIONS: set[str] = {
    "microsoft.storage/storageaccounts/write",
    "microsoft.network/networksecuritygroups/securityrules/write",
    "microsoft.keyvault/vaults/accesspolicies/write",
    "microsoft.authorization/locks/delete",
}

# Scopes that are dangerously broad when used as an assignable scope or
# assignment scope. The root management group ``/`` and bare management-group or
# subscription roots get flagged when paired with wildcard actions.
ROOT_SCOPE = "/"

WRITE_VERBS: tuple[str, ...] = ("/write", "/delete", "/action")
