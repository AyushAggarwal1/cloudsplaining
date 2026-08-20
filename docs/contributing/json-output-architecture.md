# JSON output architecture and field lineage

This document explains how Cloudsplaining builds the final JSON report, where
every report field comes from, and why it exists. It covers both report paths:

- AWS: `download` -> `scan`
- Azure, GCP, and OCI: `collect-cloud` -> `scan-cloud`

The implementation was traced through the collectors, provider engines, AWS
scanner, shared report serializer, identity-inventory builders, and tests. The
six local `op/*.json` reports were also parsed and compared structurally. No
identity names, account identifiers, policy contents, or other report values are
reproduced here.

## Reading the field maps

Paths use these placeholders:

- `{principal_id}` is a dynamic map key such as an AWS principal ID, Azure
  object ID, GCP member string, or OCI OCID.
- `{policy_id}` is a dynamic map key such as an AWS policy ID, Azure role GUID,
  GCP role name, or OCI policy OCID.
- The permission-set collection is provider-native: AWS keeps
  `aws_managed_policies` / `customer_managed_policies` / `inline_policies`,
  while `scan-cloud` reports emit a single `roles` collection (Azure and GCP)
  or `policies` collection (OCI) with a `roleType` / `policyType` field per
  entry.

There are four kinds of field provenance:

| Kind | Meaning |
| --- | --- |
| Fetched | Returned by a cloud API and copied into a snapshot. |
| Pass-through | Copied from the snapshot into the report, sometimes with a renamed key. |
| Derived | Computed from other values, relationships, risk rules, or the current time. |
| Static | Supplied by Cloudsplaining constants or configuration rather than a cloud API. |

This distinction matters because the final report is not a raw cloud response.
It is an identity-policy graph plus derived findings and lifecycle enrichment.

## End-to-end architecture

```mermaid
flowchart LR
    subgraph Cloud_APIs[Cloud APIs]
        AWS_API[AWS IAM, credential report,<br/>and CloudTrail]
        AZ_API[Azure Authorization API<br/>and Microsoft Graph]
        GCP_API[GCP IAM, Resource Manager,<br/>Policy Analyzer, and Logging]
        OCI_API[OCI Identity, Audit,<br/>and Identity Domains]
    end

    subgraph Collection[Collection layer]
        AWS_DOWNLOAD[download command]
        AZ_COLLECT[AzureCollector]
        GCP_COLLECT[GcpCollector]
        OCI_COLLECT[OciCollector]
    end

    subgraph Snapshots[Provider-native snapshots]
        AWS_SNAPSHOT[AWS authorization-details JSON]
        AZ_SNAPSHOT[Azure snapshot]
        GCP_SNAPSHOT[GCP snapshot]
        OCI_SNAPSHOT[OCI snapshot]
    end

    subgraph Analysis[Analysis and normalization]
        AWS_SCAN[AuthorizationDetails<br/>principal and policy scanners]
        AZ_ENGINE[AzureProvider]
        GCP_ENGINE[GcpProvider]
        OCI_ENGINE[OciProvider]
        MODEL[AccountModel<br/>identity-policy graph]
        MULTI_SERIALIZER[serialize.render]
    end

    subgraph Enrichment[Lifecycle enrichment]
        INVENTORY[build_identity_inventory]
        INV_MODEL[IdentityRecord serialization]
    end

    subgraph Shared_inputs[Shared analysis inputs]
        EXCLUSIONS[Exclusions YAML]
        RISK_RULES[Risk constants and<br/>provider rule sets]
        POLICY_SENTRY[policy_sentry action database]
    end

    subgraph Output[Final output]
        MERGE[Append identity_inventory]
        JSON_WRITE[JSON serialization<br/>with default=str]
        FINAL[Final report JSON<br/>including op/*.json samples]
        HTML[HTML report iam_data]
    end

    AWS_API --> AWS_DOWNLOAD --> AWS_SNAPSHOT --> AWS_SCAN
    AZ_API --> AZ_COLLECT --> AZ_SNAPSHOT --> AZ_ENGINE --> MODEL
    GCP_API --> GCP_COLLECT --> GCP_SNAPSHOT --> GCP_ENGINE --> MODEL
    OCI_API --> OCI_COLLECT --> OCI_SNAPSHOT --> OCI_ENGINE --> MODEL
    MODEL --> MULTI_SERIALIZER

    AWS_SNAPSHOT --> INVENTORY
    AZ_SNAPSHOT --> INVENTORY
    GCP_SNAPSHOT --> INVENTORY
    OCI_SNAPSHOT --> INVENTORY
    INVENTORY --> INV_MODEL

    EXCLUSIONS --> AWS_SCAN
    EXCLUSIONS --> MULTI_SERIALIZER
    RISK_RULES --> AWS_SCAN
    RISK_RULES --> AZ_ENGINE
    RISK_RULES --> GCP_ENGINE
    RISK_RULES --> OCI_ENGINE
    POLICY_SENTRY --> AWS_SCAN

    AWS_SCAN --> MERGE
    MULTI_SERIALIZER --> MERGE
    INV_MODEL --> MERGE
    MERGE --> JSON_WRITE --> FINAL
    MERGE --> HTML
```

The report's central relationship is bidirectional. Principals point to policy
IDs, while every policy records the principal names to which it is attached:

```mermaid
flowchart LR
    PRINCIPALS[users / groups<br/>plus roles on AWS]
    POINTERS[permission-set id to name pointers]
    POLICIES[AWS policy collections, or<br/>roles Azure/GCP, policies OCI]
    ATTACHED[AttachedTo<br/>users, groups; roles on AWS;<br/>public on GCP]
    CATEGORIES[Risk-category blocks]

    PRINCIPALS --> POINTERS --> POLICIES
    POLICIES --> ATTACHED --> PRINCIPALS
    POLICIES --> CATEGORIES
```

## Collection sources

### AWS

The `download` command builds one authorization-details snapshot.

| Cloud call | Snapshot fields | Reason |
| --- | --- | --- |
| IAM `GetAccountAuthorizationDetails`, paginated with `User`, `Group`, `Role`, `LocalManagedPolicy`, and `AWSManagedPolicy` filters | `UserDetailList`, `GroupDetailList`, `RoleDetailList`, `Policies` | Supplies principals, group membership, trust policies, inline policies, attached managed-policy references, managed-policy metadata, and policy versions. Only managed policies with `AttachmentCount > 0` are retained. |
| IAM `GenerateCredentialReport` and `GetCredentialReport` | `credentialReport`, `credentialReportGeneratedTime` | Supplies user credential shape, access-key records, and user/key last-used timestamps for `identity_inventory`. This is best effort. |
| IAM per-user `ListAccessKeys`, `GetLoginProfile`, and `ListMFADevices` | `credentialSupplement` | Fills the gap when a newly created user is missing from the cached credential report. This is best effort and capped at 50 users. |
| CloudTrail `LookupEvents` for identity and credential creation events | `cloudTrailEvents` | Supplies creator attribution and fallback credential evidence for `identity_inventory`. Event history is limited by CloudTrail retention and permissions. |

The `scan` command reads that snapshot; it does not call AWS APIs.

### Azure

`AzureCollector` creates the Azure snapshot.

| Cloud call | Snapshot fields | Reason |
| --- | --- | --- |
| `AuthorizationManagementClient.role_definitions.list(subscription_scope)` | `roleDefinitions[].id`, `roleName`, `roleType`, `assignableScopes`, `permissions[].actions`, `notActions`, `dataActions`, `notDataActions` | Supplies built-in/custom role definitions and the permissions analyzed as policies. |
| `role_assignments.list_for_subscription()` | `roleAssignments[].principalId`, `principalType`, `roleDefinitionId`, `scope` | Connects principals to role definitions. |
| Microsoft Graph `/users` | `users[]` | Supplies users and `id`, UPN, display name, enabled state, type, creation time, and optional sign-in activity. |
| Microsoft Graph `/groups` and `/groups/{id}/members` | `groups[]`, `groupMemberships` | Supplies groups and user-to-group relationships. |
| Microsoft Graph `/servicePrincipals` | `servicePrincipals[]` | Supplies workload identities represented as report users with `provider_kind: "service_principal"`. |
| Microsoft Graph directory audits | `directoryAudits[]` | Best-effort creator attribution for users and service principals. |
| Microsoft Graph beta service-principal sign-in report | `servicePrincipalSignInActivities[]` | Best-effort last-used data for service principals. |

Graph collection fails open. Role definitions and assignments can still produce a
report when directory or reporting permissions are unavailable.

### GCP

`GcpCollector` creates the GCP snapshot.

| Cloud call | Snapshot fields | Reason |
| --- | --- | --- |
| IAM `projects.serviceAccounts.list` | `serviceAccounts[].email`, `uniqueId`, `displayName` | Supplies service-account principals. |
| IAM `projects.roles.list(view=FULL)` | `customRoles[].name`, `title`, `stage`, `includedPermissions` | Supplies customer-managed roles and their complete permission lists. |
| Resource Manager `projects.getIamPolicy(requestedPolicyVersion=3)` | `bindings[].role`, `members`, `resource`, optional `condition` | Connects members to roles. |
| IAM `roles.get` for every referenced `roles/...` binding | `predefinedRoles[].name`, `title`, `includedPermissions` | Expands only the provider-managed roles actually used by the project. |
| Policy Analyzer `serviceAccountLastAuthentication` | `serviceAccountActivities[]` | Best-effort service-account last-used data. |
| Cloud Logging Admin Activity queries | `auditLogEntries[]` | Best-effort service-account creation/creator data, human activity, and earliest IAM-grant proxies for human creation/creator data. |

Lifecycle calls fail open and emit empty arrays when the API is disabled or the
caller lacks permission.

### OCI

`OciCollector` creates the OCI snapshot.

| Cloud call | Snapshot fields | Reason |
| --- | --- | --- |
| Identity `list_users` | `users[]` | Supplies user identity, creation, login, MFA, and capability fields. |
| Identity `list_groups` | `groups[]` | Supplies group principals. |
| Identity `list_dynamic_groups` | `dynamicGroups[]` | Supplies workload identities represented as report groups with `provider_kind: "dynamic_group"`. |
| Identity `list_policies` for the tenancy and its immediate compartments | `policies[].id`, `name`, `compartmentId`, `statements` | Supplies customer policy statements. |
| Identity `list_user_group_memberships` | `groupMemberships` | Connects users to groups. |
| Audit `list_events` around identity creation times | `auditEvents[]` | Best-effort creator attribution for users and dynamic groups. |
| Identity Domains SCIM `list_users` | `users[].idcsCreatedBy` | Best-effort durable creator attribution for Identity Domains users. |

## Top-level report fields

| Path | Type | Providers | Provenance and reasoning |
| --- | --- | --- | --- |
| `account_id` | string | All | AWS derives it from the first non-provider principal ARN in `roles`, then `users`, then `groups`. Multi-cloud reports copy the collector's subscription ID, project ID, or tenancy OCID. It is empty for older/bare inputs without account scope. |
| `provider` | string | Azure, GCP, OCI | Static provider name from `AccountModel.provider`. The legacy AWS serializer intentionally does not emit this field. |
| `groups` | object | All | Dynamic principal map. AWS builds it from `GroupDetailList`; provider engines build it from their normalized `AccountModel.groups`. OCI dynamic groups live here with `provider_kind: "dynamic_group"`. |
| `users` | object | All | Dynamic principal map. AWS builds it from `UserDetailList`; provider engines build it from enumerated or binding-inferred identities. Azure service principals/managed identities (`provider_kind: "service_principal"`) and GCP service accounts (`provider_kind: "service_account"`) live here; deleted GCP members carry `deleted: true`. |
| `roles` | object | AWS, Azure, GCP | Two different meanings. AWS: IAM roles (assumable principals). Azure/GCP: the permission-set collection — Azure role definitions with `roleType: BuiltInRole \| CustomRole`, GCP roles with `roleType: basic \| predefined \| custom` — with `RoleName`/`RoleId` entry fields. |
| `policies` | object | OCI | OCI's permission-set collection: policies with `PolicyName`/`PolicyId`, raw `statements`, parsed `GrantedAccess`, and `policyType: tenancy \| compartment` derived from the `compartmentId` prefix. |
| `aws_managed_policies` | object | AWS | Attached AWS-managed IAM policies, selected by ARN prefix. |
| `customer_managed_policies` | object | AWS | AWS customer-managed IAM policies. |
| `inline_policies` | object | AWS | AWS inline user/group/role policies. |
| `exclusions` | object | All | Pass-through of the active exclusions configuration. AWS can load a custom YAML file; `scan-cloud` currently calls the serializer with the packaged defaults. |
| `links` | object | All | AWS maps risky action names to policy_sentry documentation URLs. Multi-cloud serializers currently emit an empty object. |
| `identity_inventory` | array | All snapshot-object scans | A separate full identity census appended after policy report serialization. It is absent when `scan-cloud` receives a bare OCI statement list because that input has no identity snapshot. |

