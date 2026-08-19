"""Risk constants for GCP IAM analysis.

GCP IAM has two pieces:

* **Roles** are named collections of *permissions* of the form
  ``service.resource.verb`` (e.g. ``resourcemanager.projects.setIamPolicy``).
  Predefined roles (``roles/...``) and custom roles
  (``projects/<p>/roles/<id>``) both expand to permission sets. The three
  legacy *basic* roles ``roles/owner``, ``roles/editor`` and ``roles/viewer``
  are extremely broad.
* **Bindings** attach a role to *members* (``user:``, ``serviceAccount:``,
  ``group:``, ``domain:``, ``allUsers``, ``allAuthenticatedUsers``) on a
  resource's IAM policy.

References:
* https://cloud.google.com/iam/docs/understanding-roles
* https://cloud.google.com/iam/docs/permissions-reference
* https://cloud.google.com/iam/docs/privilege-escalation
"""

# Copyright (c) 2020, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license.
# For full license text, see the LICENSE file in the repo root
# or https://opensource.org/licenses/BSD-3-Clause
from __future__ import annotations

# Legacy "basic" roles that grant project-wide access.
BASIC_ROLES: dict[str, str] = {
    "roles/owner": "CRITICAL",
    "roles/editor": "HIGH",
    "roles/viewer": "LOW",
}

# Predefined roles whose grant is itself a privilege-escalation primitive.
PRIVILEGED_PREDEFINED_ROLES: set[str] = {
    "roles/iam.securityAdmin",
    "roles/iam.serviceAccountTokenCreator",
    "roles/iam.serviceAccountUser",
    "roles/iam.serviceAccountKeyAdmin",
    "roles/iam.workloadIdentityUser",
    "roles/resourcemanager.organizationAdmin",
    "roles/owner",
}

# Members that mean "anyone on the internet" / "any Google account".
PUBLIC_MEMBERS: set[str] = {"allusers", "allauthenticatedusers"}

# Permissions that allow a principal to grant themselves more access
# (privilege escalation). Any *.setIamPolicy is included via the suffix check
# in the engine; these are the additional well-known escalation permissions.
PRIVILEGE_ESCALATION_PERMISSIONS: set[str] = {
    "iam.serviceaccounts.actas",
    "iam.serviceaccounts.getaccesstoken",
    "iam.serviceaccounts.getopenidtoken",
    "iam.serviceaccounts.implicitdelegation",
    "iam.serviceaccountkeys.create",
    "iam.roles.update",
    "iam.roles.create",
    "deploymentmanager.deployments.create",
    "cloudfunctions.functions.create",
    "cloudfunctions.functions.update",
    "cloudbuild.builds.create",
    "compute.instances.setServiceAccount".lower(),
    "run.services.create",
    "orgpolicy.policy.set",
}

# Suffix marking IAM-policy-setting permissions on any resource type.
SET_IAM_POLICY_SUFFIX = ".setiampolicy"

# Permissions that yield credentials.
CREDENTIALS_EXPOSURE_PERMISSIONS: set[str] = {
    "iam.serviceaccountkeys.create",
    "iam.serviceaccountkeys.get",
    "container.clusters.getcredentials",
    "secretmanager.versions.access",
}

# Permissions associated with bulk data reads (exfiltration).
DATA_EXFILTRATION_PERMISSIONS: set[str] = {
    "storage.objects.get",
    "storage.objects.list",
    "bigquery.tables.getdata",
    "bigquery.tables.export",
    "spanner.databases.read",
    "datastore.entities.get",
}

# Permissions that expose resources publicly / change resource exposure.
RESOURCE_EXPOSURE_PERMISSIONS: set[str] = {
    "storage.buckets.setiampolicy",
    "compute.firewalls.create",
    "compute.firewalls.update",
    "run.services.setiampolicy",
    "cloudfunctions.functions.setiampolicy",
    "pubsub.topics.setiampolicy",
}
