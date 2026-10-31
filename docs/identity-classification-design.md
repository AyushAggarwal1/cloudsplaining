# Identity Classification Robustness — Design

Date: 2026-08-02
Status: Approved (interactive design review with Ayush)
Driver: live-scan misclassification — IAM user `ciem` (AccuKnox scanner, machine) reported as `human`.

## Problem

Every identity-inventory builder (`cloudsplaining/identity_inventory/{aws,azure,gcp,oci}.py`) makes a
silent binary human/machine guess when evidence is missing, and each implements signal precedence ad hoc.

Observed failure (AWS): a user created inside the credential-report cache window (AWS caches the report
up to 4 hours; regeneration cannot be forced) has no report row. With a neutral name (`ciem`), the
classifier hits the no-evidence default and silently reports `human`. Verified against a live scan:
`ciem` created 2026-08-02T14:37Z, scan at ~14:53Z, newest credential-report row from Jul 31 — no
`ciem` row, CreateUser CloudTrail event present (so `created_by` resolved), classification wrong.
(Account details redacted; live scan artifacts stay in gitignored `.live-scans/`.)

Same disease elsewhere:
- Azure: users classified by name heuristic alone; no structural signal at all.
- GCP: `user:` binding members with `*.gserviceaccount.com` domains classified human. (Lifecycle
  evidence for binding-only members was separately fixed on 2026-08-02 via audit-log activity and
  `SetIamPolicy` grant proxies; this design only touches GCP *classification*.)
- OCI: capabilities read only from the classic `capabilities` key; Identity Domains (SCIM) users'
  capabilities extension ignored → human default.

## Decisions (made during design review)

1. `classification` gains a third value **`unknown`** — the classifier never guesses without evidence.
2. Evidence acquisition (AWS): **live gap-user IAM lookups + extra CloudTrail events**, both best-effort.
3. Scope: **all four clouds, full depth**.
4. Architecture: **shared evidence-precedence resolver** (Approach 1), not per-cloud inline fixes,
   not a scoring engine.

## Shared framework

### `model.py`
- Add `UNKNOWN = "unknown"` alongside `HUMAN` / `MACHINE`.
- Add `IdentityRecord.classification_reason: str | None = None`, serialized by `to_dict()` as
  `classification_reason`. Every record states what it is and why.

Downstream contract change (AccuKnox platform ingests `iam-findings-*.json`): one new nullable field,
one new possible `classification` value. Recommend platform treats `unknown` as a "re-scan pending"
bucket, not a governance bucket.

### `classify.py` — resolver
Small helper: builders pass an ordered sequence of optional signals, each `(classification, reason)`
or `None` when the signal is absent; the first present signal wins; if none present, result is
`(UNKNOWN, <reason describing what was missing>)`.

Canonical precedence (identical semantics on every cloud):
1. **Hard structure** — identity kind decides: service principals, managed identities, GCP service
   accounts, OCI dynamic groups, AWS service-linked/service roles, access-key records → machine.
   Never overridable.
2. **Machine name token** — ranked above credential shape deliberately: an automation account may
   still have a password/MFA set by its owner; the name states intent. Preserves current AWS/OCI
   ordering.
3. **Credential / activity shape** — console password, MFA, interactive sign-ins, SAML trust → human;
   access-keys-only, non-interactive-only sign-ins → machine.
4. **Nothing** → `unknown` with an actionable reason.

### Name heuristics (shared)
- New tokens (whole-word semantics unchanged): `ciem`, `cspm`, `cnapp`, `siem`, `collector`,
  `exporter`, `ingest`, `devops`, `noreply`, `smtp`.
- New shared machine-domain rule for email-shaped names whose domain marks a workload
  (e.g. `*.gserviceaccount.com`).

## AWS

### Download (`command/download.py`)
- Store `credentialReportGeneratedTime` (GetCredentialReport `GeneratedTime`) in the snapshot.
- Extend CloudTrail LookupEvents fetch with `CreateAccessKey` and `CreateLoginProfile`
  (same channel, no new permissions).
- **Gap-user supplement**: diff `UserDetailList` against credential-report rows; for each user missing
  from the report (normally 0–2; safety cap with warning), call:
  - `iam:ListAccessKeys` (key statuses)
  - `iam:GetLoginProfile` (404 ⇒ no console password)
  - `iam:ListMFADevices`
  Store under `credentialSupplement: {userName: {access_keys_active, has_login_profile, mfa_devices,
  checked_at}}`. All three actions are already in `SecurityAudit` and `ReadOnlyAccess`. Best-effort
  per user AND per call; partial data kept; failures log a warning; download never fails on enrichment.

### Classification (`identity_inventory/aws.py`)
Users, through the resolver:
- Name token → machine.
- Credential shape, sources in order of authority: **supplement** (fresh) → **report row** →
  **CloudTrail events** (CreateLoginProfile seen ⇒ human; CreateAccessKey and no CreateLoginProfile
  ⇒ machine).
- Report row present but zero credentials (no password, no keys, no MFA) → `unknown`,
  reason `"no credentials provisioned"`. (Behavior change: today silently human.)
- Nothing anywhere → `unknown` with a stable, matchable reason. The builder compares
  `created_at` with `credentialReportGeneratedTime`: a later user gets `"created after credential
  report was generated"`; a pre-existing user gets `"credential report row missing for pre-existing
  user"`. Missing comparison timestamps are stated explicitly. No report yields
  `"no credential evidence: credential report unavailable"`.

Roles: service-role path → machine; IAM Identity Center reserved path/name or SAML trust → human;
otherwise machine (`"workload role"`). Access-key child records → machine (`"access key"`).

Outcome for the driver case: `ciem` → machine once the supplement runs or its CreateAccessKey event
lands; honestly `unknown` (never falsely human) in the seconds-old worst case.

## Azure

Service principals: machine (`"service principal"`). Users:
1. Name token on UPN local part or displayName → machine. Exact-match automation accounts:
   UPN prefix `Sync_`, displayName `On-Premises Directory Synchronization Service Account` → machine.
2. Sign-in shape, gated by a **dataset-level availability check** (any user in the snapshot carrying
   `signInActivity` ⇒ tenant had permission + license, so per-user absence is meaningful):
   - any interactive sign-in (`lastSignInDateTime` / `lastSuccessfulSignInDateTime`) → human;
   - only non-interactive sign-ins → machine (`"non-interactive sign-ins only"`);
   - no sign-ins ever → `unknown` (`"never signed in"`).
3. Sign-in data unavailable tenant-wide (no `AuditLog.Read.All` / no Entra P1): soft default **human**
   with reason `"Entra user (sign-in data unavailable)"` — an Entra user object is a people-directory
   entry by construction, unlike an AWS IAM user; the reason keeps the soft default honest.

If Graph identity collection is unavailable, subscription RBAC assignments still produce honest
fallback rows: users are `unknown` and service principals are `machine`; the principal ID is used
as both `id` and `name`, and lifecycle fields stay null.

## GCP

- Service accounts: machine (`"service account"`).
- `user:` binding member with `*.gserviceaccount.com` domain → machine (shared domain rule).
- Workspace directory users: name token → machine; else human (`"Workspace directory user"`).
  Never-logged-in stays human; `last_used: null` carries dormancy.
- Binding-only members: name/domain rules; else human (`"user: IAM binding member"`).
- GCP rarely emits `unknown` — honest, since member types are structural.
- Lifecycle enrichment (audit-log `last_used`, `SetIamPolicy` grant proxies for
  `created_at`/`created_by`) already landed separately; classification builds on top unchanged.

## OCI

Dynamic groups: machine (`"workload identity"`). Users (capabilities read from BOTH the classic
`capabilities` key AND the SCIM extension `urn:ietf:params:scim:schemas:oracle:idcs:extension:capabilities:User`,
fixing the ignored-SCIM bug):
1. Name token → machine.
2. MFA enrolled → human (`"MFA enrolled"` — enrollment is current state).
3. Console password disabled + API keys enabled → machine (`"API-key-only capabilities"`).
   Ranked above login history deliberately: an account converted to a service user keeps its old
   login timestamp, but its current shape is a machine. (Refined during implementation — an
   existing collector test exposed the converted-account case.)
4. Successful console login recorded → human (`"console login recorded"`).
5. Console-capable → human (`"console-capable (default)"` — soft, creation default).
6. Nothing → `unknown` (behavior change: today silently human).

## Degradation & error handling

- Every enrichment optional, best-effort; absence degrades toward `unknown` or a documented soft
  default; never crashes; never fails a download or scan.
- AWS supplement best-effort per user and per call; partial data kept; one warning per failure.
- Malformed enrichment payloads tolerated (existing defensive parsing style).
- `unknown` always carries a reason. Reason strings form a small documented vocabulary; platform may
  match on them; changes kept additive.

## Testing (TDD, repo standard)

- Resolver: parameterized precedence-table test — each layer beats all lower layers; nothing → unknown.
- AWS — ciem reproduction trio:
  1. gap user + CreateAccessKey event → machine;
  2. gap user + supplement showing password → human;
  3. gap user + nothing → unknown with created-after-report reason.
  Plus: zero-credential row → unknown; supplement beats stale report row; moto tests for download
  (GeneratedTime storage, supplement calls, new event names).
- Azure: interactive / non-interactive / never matrix; availability soft default; sync-account names.
- GCP: gserviceaccount `user:` member → machine; reasons on unchanged classifications.
- OCI: SCIM capabilities extension honored; capabilities absent → unknown; login-activity → human.
- Name heuristics: new tokens, whole-word behavior, machine-domain rule.
- Fixtures: `just generate-report` + `just check-sampledata-sync` + report-regression-check
  (identity_inventory rides inside results JSON).

## Docs

In `docs/` root (user preference):
- Classification precedence + reason vocabulary.
- Per-cloud permissions updates: AWS three IAM read actions (already inside SecurityAudit /
  ReadOnlyAccess); Azure `AuditLog.Read.All` + Entra P1 note for sign-in data; GCP/OCI: none new.

## Out of scope (revisit on first real need)

- Operator override config (pin classifications per name/pattern).
- OIDC human-federation detection for AWS roles.
- GCP group expansion.
- Per-access-key last-used calls (`GetAccessKeyLastUsed`).
