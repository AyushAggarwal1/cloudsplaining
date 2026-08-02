# Identity Inventory — Cloud Permissions

Permissions needed to collect the identity lifecycle inventory (`classification`, `created_at`,
`age_days`, `days_since_last_used`, `created_by`, `last_used`) per cloud, split into the **core**
permission each cloud requires and the **optional enrichments**. Everything in the enrichment tier
is best-effort: if the credential lacks it, the download/collect still succeeds and the affected
fields are `null` — nothing is guessed.

See [identity-inventory-design.md](identity-inventory-design.md) for how each field is derived.

## AWS (`cloudsplaining download`)

| Permission | What it powers | If missing |
|---|---|---|
| `iam:GetAccountAuthorizationDetails` | **Core** — users, roles, `created_at`, role `last_used`, SSO/service-linked classification | download fails (required) |
| `iam:GenerateCredentialReport` + `iam:GetCredentialReport` | Credential-shape classification (console password / MFA / active access keys → machine), user `last_used`, access-key child rows | classification falls back to name heuristics; user `last_used` null; no access-key rows (`--skip-credential-report` opts out explicitly) |
| `cloudtrail:LookupEvents` | `created_by` for users/roles created in the last 90 days | `created_by` null except access keys, whose structural attribution to the owning user needs no extra permission (`--skip-cloudtrail-events` opts out explicitly) |

A read-only role with the AWS-managed `SecurityAudit` policy covers all three.

## Azure (`AzureCollector`)

| Permission | What it powers | If missing |
|---|---|---|
| **Reader** role on the subscription (ARM) | **Core** — role definitions + assignments | collect fails |
| Graph `Directory.Read.All` | users, groups, service principals, `created_at`, classification | identity list empty (logged warning; role-based report still produced) |
| Graph `AuditLog.Read.All` **+ Entra ID P1/P2 license** | user `signInActivity` → `last_used` | collector auto-retries without `signInActivity`; user `last_used` null |
| Graph `AuditLog.Read.All` | `directoryAudits` ("Add user" / "Add service principal") → `created_by` (~30-day retention) | `created_by` null |
| Graph `Reports.Read.All` | `servicePrincipalSignInActivities` (Graph beta) → service-principal `last_used` | SP `last_used` null |

## GCP

| Permission | What it powers | If missing |
|---|---|---|
| `iam.serviceAccounts.list` + `resourcemanager.projects.getIamPolicy` (e.g. `roles/viewer`) | **Core** — service accounts, binding members, structural classification, SA `created_at` | no identities |
| `policyanalyzer.serviceAccountLastAuthenticationActivities.query` (`roles/policyanalyzer.activityAnalysisViewer`) | SA `last_used` (Policy Analyzer `lastAuthenticatedTime`) | null |
| `logging.logEntries.list` (`roles/logging.viewer`) for `CreateServiceAccount` audit entries (~400-day retention) | SA `created_by` (and `created_at` fallback) | null |
| Workspace Admin SDK `admin.directory.user.readonly` | human users' `created_at` / `last_used` (`creationTime` / `lastLoginTime`) | users appear only as binding members with lifecycle fields null |

## OCI

| Permission (IAM policy statement) | What it powers | If missing |
|---|---|---|
| `Allow group <X> to read users in tenancy` plus `inspect groups`, `inspect dynamic-groups`, `inspect policies`, `inspect compartments` | **Core** — `ListUsers` already returns `timeCreated`, `lastSuccessfulLoginTime`, `isMfaActivated`, and `capabilities`, so classification + `created_at` + `last_used` need nothing extra | no identities |
| `Allow group <X> to read audit-events in tenancy` (365-day retention) | `created_by` via create-user / create-dynamic-group events | null — unless the tenancy uses Identity Domains, where `idcsCreatedBy` comes free with the user record |

## Summary

- **AWS and OCI**: a standard read-only auditor credential yields all six fields (minus
  `created_by` for identities older than the audit-log retention window).
- **Azure**: user `last_used` and `created_by` gate on an extra Graph permission
  (`AuditLog.Read.All`) *and*, for sign-in activity, a paid Entra ID P1/P2 license.
- **GCP**: full coverage needs three separate APIs — Policy Analyzer, Cloud Logging, and the
  Workspace Admin SDK — on top of the core IAM read access.
