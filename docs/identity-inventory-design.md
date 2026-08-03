# Identity Lifecycle Inventory — Design

**Status:** implemented (pending review) · **Date:** 2026-08-01

## Goal

For every identity in AWS, Azure, GCP, and OCI (Oracle), produce a normalized record with:

1. `classification` — `machine`, `human`, or `unknown` (never a silent guess), with a
   `classification_reason` stating the evidence (see the vocabulary below and
   `identity-classification-design.md`)
2. `created_at`
3. `age_days`
4. `days_since_last_used`
5. `created_by`
6. `last_used`

plus identifying fields (`provider`, `identity_type`, `id`, `name`) so each row is attributable.

## Approaches considered

- **A. Extend the existing multicloud engines/collectors and AWS scan classes** to carry lifecycle
  fields into the HTML report. Invasive: touches `scan/`, all three engines, the report schema, and
  the Vue bundle. High regression surface for a data need that is tabular, not report-shaped.
- **B. Self-contained `cloudsplaining/identity_inventory/` package (chosen).** Pure offline
  builders: each takes that cloud's already-exported JSON (the same snapshot shapes
  `cloudsplaining/multicloud/collectors/` produce, or the cloud's native CLI/API export) and returns
  normalized `IdentityRecord`s. Zero risk to the existing pipeline, fully unit-testable, and the
  collectors can later be extended to enrich their snapshots with the lifecycle fields.
- **C. New live collectors calling cloud APIs directly from the new folder.** Duplicates the auth
  plumbing that already exists in `multicloud/collectors/` and cannot be tested without credentials.

## Architecture (approach B)

```
cloudsplaining/identity_inventory/
├── __init__.py      # public API: build_identity_inventory, IdentityRecord, ...
├── model.py         # IdentityRecord dataclass; derives age_days / days_since_last_used
├── parsing.py       # tolerant ISO-8601 parsing + camel/kebab/snake key lookup, day-diff helpers
├── classify.py      # shared machine-vs-human name heuristics (token-based, no substring FPs)
├── aws.py           # authorization-details JSON (+ optional credential report / CloudTrail events)
├── azure.py         # Graph users/servicePrincipals (+ optional SP sign-in activity / audit logs)
├── gcp.py           # serviceAccounts + Workspace users + bindings (+ audit logs / Policy Analyzer)
├── oci.py           # IAM / Identity Domains users + dynamic groups (+ audit events)
├── inventory.py     # provider dispatcher ("oracle" aliases to oci), dict/CSV serialization
└── __main__.py      # click CLI: python -m cloudsplaining.identity_inventory
```

**Scan integration:** both scan commands embed the inventory in their JSON output under a top-level
`identity_inventory` key (a list of serialized records). The AWS `scan` command adds it to
`iam-results-*.json` / `iam-findings-*.json` (and hence the report's `iam_data` blob — the Vue UI
ignores the extra key), computed from the same authorization-details input. `scan-cloud` adds it to
its JSON/HTML report from the same snapshot, for dict inputs (OCI statement-list paste mode carries
no identities). The inventory is a full census: finding exclusions do not filter it, and derived
ages are computed at scan time.

Every builder has the same signature: `build_inventory(data: dict) -> list[IdentityRecord]` — a pure
parse that stores raw datetimes. The derived fields are computed at serialization time
(`IdentityRecord.to_dict(reference_time=...)` / `build_identity_inventory(..., reference_time=...)`);
`reference_time` (default: now, UTC) makes `age_days` / `days_since_last_used` deterministic and
testable. Unknown values are `None`, never guessed. All key lookups tolerate camelCase, kebab-case,
and snake_case (OCI CLI emits kebab-case; SDKs emit snake_case; REST APIs camelCase).

## Identity types and classification rules

Every builder feeds ordered evidence into a shared first-signal-wins resolver
(`classify.resolve`): hard structure → machine-name → credential/activity shape → `unknown`.
No evidence means `unknown`, never a guess.

| Provider | Identity types | machine when | human when | unknown when |
|---|---|---|---|---|
| aws | `user`, `role`, `access_key` | role (workload default); service-role path; access-key records; machine-token name; active access keys + no console password/MFA (live supplement, credential report, or CloudTrail credential events) | console password or MFA; SAML-federated role trust | no credential report available; user created after the cached report was generated with no supplement/events; report row with zero credentials |
| azure | `user`, `service_principal` | any service principal; machine-token or sync-account name; only non-interactive sign-ins | interactive sign-ins; soft default with reason when the tenant has no sign-in data (no `AuditLog.Read.All`/P1) | sign-in data available but the user never signed in |
| gcp | `user`, `service_account` | every service account; machine-token name; `user:` member with a `*.gserviceaccount.com` domain | Workspace directory user; `user:` binding member | — (member types are structural) |
| oci | `user`, `dynamic_group` | dynamic group; machine-token name; API keys + console password disabled (classic `capabilities` or the Identity Domains SCIM capabilities extension) | MFA enrolled; console login recorded; console-capable (soft default, stated in the reason) | no capability or activity evidence |

**API-backed signals (fetched automatically):**

- **AWS** — `download` generates and embeds the IAM credential report (`credentialReport` key plus
  `credentialReportGeneratedTime`; `--skip-credential-report` opts out, permission failures degrade
  gracefully). It powers the credential-shape rule and user last-used. AWS serves a **cached**
  report for up to four hours, so users created after generation have no row; for them `download`
  performs live per-user lookups (`iam:ListAccessKeys` / `iam:GetLoginProfile` /
  `iam:ListMFADevices`, all inside `SecurityAudit`) stored under `credentialSupplement`.
  `download` also pages CloudTrail `LookupEvents` for
  `CreateUser`/`CreateRole`/`CreateAccessKey`/`CreateLoginProfile` (`cloudTrailEvents` key;
  `--skip-cloudtrail-events` opts out) — `created_by` attribution plus credential-shape
  corroboration for report-gap users. Each existing access key additionally becomes a child
  `access_key` record whose `created_by` is the owning user (structural attribution that never
  expires), with `created_at` = last rotation and the key's own last-used date.
- **OCI** — the collector serializes `capabilities`, `isMfaActivated`, `timeCreated`,
  `lastSuccessfulLoginTime`, and `email` straight from `ListUsers` (no extra calls). It also
  queries OCI Audit `ListEvents` in short padded windows around each identity's `timeCreated`
  (where its creation event lives; observed skew ~0.1s), newest identity first, merged when
  close, clamped a day inside the service's rolling 365-day `startTime` validation, and
  page-capped per window and globally so noisy tenancies stay fast. Kept
  `CreateUser`/`CreateDynamicGroup` events (`auditEvents` key) power `created_by` — first event
  per name wins, so a deleted namesake's older event never overrides the current identity.
  Fails open to null without the `read audit-events` permission; identities older than the
  retention window stay null. Identity
  Domains (SCIM) users carry capabilities in the
  `urn:ietf:params:scim:schemas:oracle:idcs:extension:capabilities:User` extension, which is read
  too. Precedence: machine-token name → MFA enrolled (current human state) → API-key-only
  capabilities (current machine shape — deliberately above historical logins, which survive
  conversion to a service account) → console login recorded → console-capable soft default →
  `unknown`.
- **Azure** — the collector requests `createdDateTime`, `userType`, `accountEnabled`, and
  `signInActivity` for users (falling back without `signInActivity` when the tenant lacks
  `AuditLog.Read.All` / Entra ID P1) and `createdDateTime` for service principals. Interactive
  sign-ins → human; only non-interactive → machine; never signed in (with data available) →
  `unknown`; no sign-in data tenant-wide → soft human default with the reason stating so.
  Well-known AD Connect sync accounts (`Sync_*` UPNs, the on-premises directory synchronization
  display name) → machine.
- **GCP** — the service-account vs. user split from the IAM API is already the authoritative
  classification signal. Human users' lifecycle comes from Admin Activity audit logs
  (`auditLogEntries`): their newest logged activity → `last_used`, and the first `SetIamPolicy`
  grant that added the `user:` member → proxy `created_at` + `created_by` (~400-day window).
  The Workspace Admin SDK scope (`admin.directory.user.readonly`) is deliberately **not**
  required; a Workspace `users.list` export is honored if supplied (`creationTime` authoritative,
  `lastLoginTime` merged into `last_used`).

Name heuristic (`classify.py`): a name is machine-like when a token such as `svc`, `service`, `bot`,
`ci`, `ciem`, `cicd`, `cspm`, `cnapp`, `siem`, `deploy`, `devops`, `automation`, `jenkins`,
`terraform`, `github`, `pipeline`, `lambda`, `backup`, `agent`, `collector`, `exporter`, `ingest`,
`noreply`, `smtp`, ... appears delimited by `-`/`_`/`.`/digits or string edges — so `svc-deployer`
and `backup_agent` match, but `apparna` and `robotics-team-lead` style substrings do not. Email
names whose domain marks a workload (`*.gserviceaccount.com`) are machines regardless of local part.

### Classification reason vocabulary

Every record carries `classification_reason` — a stable string the platform may match on
(changes are additive). The full vocabulary:

| classification | reasons |
|---|---|
| machine | `automation-style name (token: <token>)` · `workload email domain (gserviceaccount.com)` · `active access keys, no console password (credential report)` / `(live IAM lookup)` · `access key created, no console password (CloudTrail events)` · `access key` · `AWS service role` · `workload role` · `service principal` · `directory synchronization account` · `non-interactive sign-ins only` · `service account` · `workload identity` · `API-key-only capabilities` |
| human | `console password or MFA (credential report)` / `(live IAM lookup)` · `console login profile created (CloudTrail events)` · `SAML-federated role` · `interactive sign-ins` · `Entra user (sign-in data unavailable)` (soft default) · `Workspace directory user` · `user: IAM binding member` · `MFA enrolled` · `console login recorded` · `console-capable (default)` (soft default) |
| unknown | `no credential evidence: credential report unavailable` · `created after credential report was generated` · `no credentials provisioned (credential report)` / `(live IAM lookup)` · `never signed in` · `no capability or activity evidence` |

## Per-cloud field sources

| Field | aws | azure | gcp | oci |
|---|---|---|---|---|
| `created_at` | `CreateDate` (authorization details) | `createdDateTime` | SAs: `createTime` if exported, else audit-log `CreateServiceAccount` entry; users: Workspace `creationTime` if supplied, else first `SetIamPolicy` audit entry that ADDed the `user:` member | `time-created` / `meta.created` |
| `last_used` | roles: `RoleLastUsed.LastUsedDate`; users: max of credential-report `password_last_used`, `access_key_*_last_used_date` | users: max of `signInActivity.{lastSignInDateTime,lastNonInteractiveSignInDateTime}`; SPs: `servicePrincipalSignInActivities` (by `appId`) | SAs: Policy Analyzer `serviceAccountLastAuthentication` (`lastAuthenticatedTime`); users: newest of audit-log activity (`authenticationInfo.principalEmail`) and Workspace `lastLoginTime` if supplied | `lastSuccessfulLoginTime` / identity-domains `userState.lastSuccessfulLoginDate` |
| `created_by` | optional `cloudTrailEvents` (`CreateUser`/`CreateRole`, raw LookupEvents or simplified) | optional `directoryAudits` (`Add user` / `Add service principal`, `initiatedBy`) | SAs: `CreateServiceAccount` caller; users: `SetIamPolicy` granter (audit logs) | `idcsCreatedBy` (identity domains) or optional `auditEvents` |
| `age_days` | derived: `(reference_time - created_at).days` | ← | ← | ← |
| `days_since_last_used` | derived: `(reference_time - last_used).days`; `None` when never used/unknown | ← | ← | ← |

Optional enrichment inputs ride along as extra top-level keys of the same input dict
(`credentialReport`, `cloudTrailEvents`, `servicePrincipalSignInActivities`, `directoryAudits`,
`auditLogEntries`, `serviceAccountActivities`, `auditEvents`) so one file per cloud is enough. The
docstring of each builder documents the CLI commands that produce each piece.

## Error handling

- Unparsable/absent timestamps → `None` (and `None` derived fields); never raises on messy exports.
- Unknown provider name → `ValueError` listing supported providers (mirrors `multicloud/provider.py`).
- Naive datetimes are assumed UTC.

## Testing

`test/identity_inventory/` (unittest style, mirrors `test/multicloud/`): model derivation math,
timestamp parsing, name heuristics (incl. false-positive guards), one test module per provider
covering classification + all six fields + enrichment inputs, dispatcher aliasing, and the CLI
(JSON + CSV) via click's `CliRunner`. TDD: tests written first, red, then implementation to green.

## Reference

The record shape and classification goal follow the non-human-identity inventory model of
[NHInsight](https://github.com/cvemula1/NHInsight) (providers per cloud → normalized identity model
→ classification + age/last-used/creator analysis), scoped here to the six requested fields and
offline snapshot inputs. NHInsight's AWS credential signals (`get_login_profile` console access,
`list_mfa_devices` MFA) are adopted in offline form via the credential report's
`password_enabled` / `mfa_active` / `access_key_*_active` columns; where NHInsight scores signals
and allows an `unknown` verdict, this design keeps a deterministic binary ladder (type → credential
shape → name tokens) per the requirement.

## Out of scope (YAGNI)

- No report-UI rendering of the inventory (the key rides along in `iam_data` unrendered), no live
  API calls, no new dependencies.
- Existing collectors/engines and the committed example fixtures untouched (the fixture generator
  builds from `AuthorizationDetails.results` directly, below the scan-command layer); enriching
  collector snapshots with lifecycle fields is a follow-up, as is embedding the inventory in
  `scan-multi-account` output.
