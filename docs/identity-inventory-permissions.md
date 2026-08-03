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
| `iam:GenerateCredentialReport` + `iam:GetCredentialReport` | Credential-shape classification (console password / MFA / active access keys → machine), user `last_used`, access-key child rows, `credentialReportGeneratedTime` | neutral-named users classify `unknown` (`no credential evidence: credential report unavailable`); user `last_used` null; no access-key rows (`--skip-credential-report` opts out explicitly) |
| `iam:ListAccessKeys` + `iam:GetLoginProfile` + `iam:ListMFADevices` | `credentialSupplement` — live classification of users created **after** the cached credential report was generated (AWS caches it up to 4 hours and regeneration cannot be forced) | such users classify from CloudTrail credential events, else `unknown` (`created after credential report was generated`) |
| `cloudtrail:LookupEvents` | `created_by` for users/roles created in the last 90 days; `CreateAccessKey`/`CreateLoginProfile` events corroborate credential shape for report-gap users | `created_by` null except access keys, whose structural attribution to the owning user needs no extra permission (`--skip-cloudtrail-events` opts out explicitly) |

A read-only role with the AWS-managed `SecurityAudit` policy covers all of the above.

## Azure (`AzureCollector`)

| Permission | What it powers | If missing |
|---|---|---|
| **Reader** role on the subscription (ARM) | **Core** — role definitions + assignments | collect fails |
| Graph `Directory.Read.All` | users, groups, service principals, `created_at`, classification | identity list empty (logged warning; role-based report still produced) |
| Graph `AuditLog.Read.All` **+ Entra ID P1/P2 license** | user `signInActivity` → `last_used` **and** sign-in-shape classification (interactive → human, non-interactive-only → machine, never → `unknown`) | collector auto-retries without `signInActivity`; user `last_used` null; users soft-default to human with reason `Entra user (sign-in data unavailable)` |
| Graph `AuditLog.Read.All` | `directoryAudits` ("Add user" / "Add service principal") → `created_by` (~30-day retention) | `created_by` null |
| Graph `Reports.Read.All` | `servicePrincipalSignInActivities` (Graph beta) → service-principal `last_used` | SP `last_used` null |

## GCP

Enable - policyanalyzer.googleapis.com
| Permission | What it powers | If missing |
|---|---|---|
| `iam.serviceAccounts.list` + `resourcemanager.projects.getIamPolicy` (e.g. `roles/viewer`) | **Core** — service accounts, binding members, structural classification, SA `created_at` | no identities |
| `policyanalyzer.serviceAccountLastAuthenticationActivities.query` (`roles/policyanalyzer.activityAnalysisViewer`) | SA `last_used` (Policy Analyzer `lastAuthenticatedTime`) | null |
| `logging.logEntries.list` (`roles/logging.viewer`) — Admin Activity audit entries, always on, free, ~400-day retention | SA `created_by`/`created_at` (`CreateServiceAccount`); human users' `last_used` (their newest logged activity) and proxy `created_at`/`created_by` (the `SetIamPolicy` grant that first added the user, plus who granted it) | null |

Human users' lifecycle comes entirely from the audit logs above — the Workspace Admin SDK scope
(`admin.directory.user.readonly`) is **deliberately not required**: it needs a Workspace Super Admin
to set up domain-wide delegation and only adds the Google-account creation date and console-login
time. If a Workspace `users.list` export is supplied anyway, the builder uses its `creationTime`
as authoritative and takes the newest of `lastLoginTime` and audit activity for `last_used`.
Semantics of the audit-log substitute: `last_used` means "last activity *in GCP*" (read-only calls
only appear if Data Access logs are enabled) and `created_at` means "when the user was first
granted GCP access", both bounded by the 400-day retention window.

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
- **GCP**: full coverage needs two extra APIs — Policy Analyzer and Cloud Logging — on top of the
  core IAM read access. No Workspace Admin SDK scope is needed: audit logs supply human users'
  `last_used` and proxy `created_at`/`created_by` (400-day window).
