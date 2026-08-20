# Multi-cloud report schema: provider-native keys

**Date:** 2026-08-19
**Status:** Approved design, pending implementation
**Scope:** `cloudsplaining/multicloud/` + `command/scan_cloud.py` / `command/access_map_cloud.py` + `test/multicloud/` + docs. **The AWS pipeline (`cloudsplaining/scan/`, `cloudsplaining/output/`, `command/scan.py`) is explicitly out of scope and must not change** — verified: it has no imports from `multicloud`.

## Problem

The multi-cloud report (`scan-cloud -o json`) force-fits every provider into the AWS report shape (`model.py` documents this as a design goal). The result misrepresents each provider's IAM model:

- **Azure** role definitions land in `azure_managed_policies` (927 built-in) + `customer_managed_policies` (21 custom), while the top-level `roles` key holds service principals. In Azure vocabulary, "policy" means Azure Policy — a different governance product — and role definitions *are* natively called roles.
- **GCP** roles land in `gcp_managed_policies` (predefined) + `customer_managed_policies` (custom). In GCP vocabulary this is backwards: a GCP "policy" is the bindings document on a resource; the permission sets are roles. Service accounts are mixed into `users` with only a metadata marker; public members (`allUsers`) are synthesized as fake "role" principals.
- **OCI** has no roles concept at all, yet dynamic groups are emitted under `roles`; `oci_managed_policies` is always empty; policies hide under `customer_managed_policies`.

## Decisions (settled with the user)

1. **Clean break.** Old keys disappear; no aliases, no schema_version. The consuming pipeline updates in lockstep.
2. **No separate workload-identity keys.** Individual principals fold into `users` discriminated by `provider_kind`; OCI dynamic groups fold into `groups`.
3. **One permission-set collection per provider** (`roles` for azure/gcp, `policies` for oci) with a type field per entry, instead of managed/customer bucket pairs.
4. **OCI `policyType` = `"tenancy" | "compartment"`**, derived from whether `compartmentId` starts with `ocid1.tenancy`.
5. **AWS code untouched.** `aws.json` report shape unchanged.

## Target schema

Unchanged top-level keys for all providers: `account_id`, `provider`, `exclusions`, `links` (still emitted, empty for non-AWS), `identity_inventory` (platform contract, built from the snapshot independently).

### Azure

```jsonc
{
  "users": {           // Entra users AND service principals / managed identities
    "<objectId>": {
      "id": "...", "name": "...",
      "provider_kind": "user" | "service_principal",
      "roles": { "<roleDefId>": "<roleName>" },   // single pointer dict
      "groups": ["..."],                           // membership (users only)
      "is_excluded": false
      // + passthrough metadata: displayName, accountEnabled, servicePrincipalType
    }
  },
  "groups": { /* Entra groups, provider_kind: "group" */ },
  "roles": {           // role definitions, built-in + custom merged
    "<roleDefGuid>": {
      "RoleName": "AcrPush",
      "RoleId": "<guid>",
      "roleType": "BuiltInRole" | "CustomRole",   // raw API value; default BuiltInRole when absent
      "AttachmentCount": 0,
      "AttachedTo": { "users": [], "groups": [] },
      "assignableScopes": [], "Actions": [], "DataActions": [], "NotActions": [],
      "PolicyVersionList": [ /* kept: raw permissions blocks carrier */ ],
      "PrivilegeEscalation": {}, /* ...all finding category blocks... */
      "is_excluded": false
    }
  }
}
```

### GCP

```jsonc
{
  "users": {           // humans + service accounts
    "user:alice@example.com":            { "provider_kind": "user", "roles": {}, ... },
    "serviceAccount:sa@p.iam.gserviceaccount.com": {
      "provider_kind": "service_account", "roles": {}, ...
      // deleted:serviceAccount:... members keep the raw member string as id,
      // email as name, and carry "deleted": true
    }
  },
  "groups": { /* group: and domain: members */ },
  "roles": {
    "roles/aiplatform.user": {
      "RoleName": "roles/aiplatform.user",
      "RoleId": "roles/aiplatform.user",
      "roleType": "basic" | "predefined" | "custom",
      // basic: name in BASIC_ROLES (owner/editor/viewer); predefined: "roles/*"; else custom
      "IncludedPermissions": [],
      "AttachmentCount": 1,
      "AttachedTo": { "users": [], "groups": [], "public": [] },
      // public: raw "allUsers"/"allAuthenticatedUsers" member strings —
      // no synthetic principal entries are created for them; the
      // PublicAccess finding on the role remains
      "stage": null, "title": "...",
      "PolicyVersionList": [],
      /* finding category blocks */, "is_excluded": false
    }
  }
}
```

Unknown/other member types (e.g. WIF `principal://`) map to `users` with `provider_kind: "unknown"`, raw member string as id.

### OCI

```jsonc
{
  "users":  { /* provider_kind: "user" */ },
  "groups": {          // groups AND dynamic groups (statements address them alike)
    "<ocid>": { "provider_kind": "group" | "dynamic_group",
                "policies": { "<policyOcid>": "<policyName>" },
                "matchingRule": "..." /* dynamic groups only */, ... }
  },
  "policies": {        // renamed from customer_managed_policies
    "<policyOcid>": {
      "PolicyName": "AuditSCC",
      "PolicyId": "<ocid>",
      "policyType": "tenancy" | "compartment",  // compartmentId startswith "ocid1.tenancy" -> tenancy
      "statements": ["Allow group AuditSecurity to read all-resources in tenancy"],
      "GrantedAccess": ["read all-resources in tenancy"],
      "compartmentId": "<ocid>",
      "AttachmentCount": 1,
      "AttachedTo": { "users": [], "groups": [] },
      "PolicyVersionList": [],
      /* finding category blocks */, "is_excluded": false
    }
  }
}
```

### Removed keys (non-AWS reports)

`azure_managed_policies`, `gcp_managed_policies`, `oci_managed_policies`, `customer_managed_policies`, `inline_policies`; the `roles` sub-key of `AttachedTo`; the per-principal three-way pointer dicts (replaced by the single `roles`/`policies` dict).

## Implementation

### `multicloud/model.py`
- Principal kinds: `USER`, `GROUP` only. `ROLE` constant and the `AccountModel.roles` bucket are deleted. Workload identities are users with `provider_kind` metadata; dynamic groups are groups with `provider_kind` metadata.
- `Policy.kind` (`MANAGED`/`CUSTOMER`/`INLINE` constants) and `policies_of_kind()` are deleted; the type lives in entry metadata (`roleType`/`policyType`), set by each engine.
- `Principal` gets one `permission_sets: dict[str, str]` pointer dict (replaces `managed_policies`/`customer_managed_policies`/`inline_policies`).
- `Policy.attached_to` defaults to `{"users": [], "groups": []}`; the GCP engine appends a `"public"` list.
- `attach()` loses its kind-branching.

### Engines
- **azure/engine.py**: `_PRINCIPAL_KIND` maps serviceprincipal/managedidentity/msi → `USER` with `provider_kind: "service_principal"`; unknown principalType fallback likewise. Role definitions always emit `roleType` (raw value, default `"BuiltInRole"`). `provider_kind: "user"` on Entra users.
- **gcp/engine.py**: emit `roleType` per the basic/predefined/custom rule (reference-policy path included). Every GCP policy initializes `attached_to["public"] = []` so the key is always present in the contract. `deleted:` member prefix → stripped, `deleted: true` on the entry, name = email portion. Public members → `attached_to["public"]` + PublicAccess finding, no principal. Unknown members → users, `provider_kind: "unknown"`.
- **oci/engine.py**: dynamic groups → `GROUP` with `provider_kind: "dynamic_group"` (both the `dynamicGroups` snapshot list and principals synthesized from `dynamic-group` statement subjects); policy entries emit `policyType` from the compartmentId prefix rule.

### Serializer
- `multicloud/report_aws.py` → **renamed `multicloud/serialize.py`** (its "AWS-shaped" premise no longer holds). `render(model, exclusions)` keeps its signature but emits the provider-native shape.
- `managed_policies_key()` deleted. `policy_collection_keys(report)` → `permission_collection_key(report)` returning `"roles"` (azure/gcp) or `"policies"` (oci), driven by the report's `provider` field.
- Principal serialization: single pointer dict named `roles`/`policies` per provider; `provider_kind` from metadata (defaults `user`/`group`).
- Exclusion semantics note: service principals / service accounts are now matched against **User** exclusion patterns (previously Role patterns); dynamic groups against Group patterns. Default exclusions contain no non-AWS names, so no behavior change is expected in practice.

### Consumers
- **`multicloud/report.py`** (console/HTML): identity collections → `("users", "groups")`; entry name getter falls back `RoleName` → `PolicyName`; AttachedTo rendering includes `public`.
- **`multicloud/access_map.py`**: iterate the provider's permission collection; the `policyType` row/CSV field now carries the entry's `roleType`/`policyType` value; `roles` column replaced by `public`.
- **`command/scan_cloud.py`**: severity filter + CI exit-code check use the new helper. `identity_inventory` injection unchanged.
- Docstrings referencing the AWS shape (`model.py`, `provider.py`, `report.py`) rewritten.

### Out of scope
AWS engine/report/CLI, `multicloud/collectors/` (input side — snapshot schema unchanged), `multicloud/analysis.py`, `multicloud/findings.py`, `identity_inventory/` (platform contract), `links` population.

## Testing (TDD, unittest-style like the existing suite)

Update `test/multicloud/` first, then make it pass:
- `test_report_aws.py` → **`test_serialize.py`**: per provider, pin the new top-level keys, assert the removed keys are absent, pin entry field names (`RoleName`/`RoleId` vs `PolicyName`/`PolicyId`), pointer dict names, `AttachedTo` sub-keys.
- Engine tests: Azure SP → users with `provider_kind`; GCP roleType derivation (all three values), public → `AttachedTo.public` with no principal, `deleted:` flag; OCI dynamic group → groups, `policyType` tenancy vs compartment.
- `test_collectors.py`: update its use of the renamed helper.
- Gate: `just pre-push`.

## Verification limits

`sample-reports/*.json` are outputs from real accounts (untracked; never commit). They cannot be regenerated in-repo without the input snapshots, so end-to-end verification on real data happens when the user re-runs the collection pipeline; in-repo verification is the test suite.

## Docs

Rewrite the schema section of `docs/multi-cloud-support.md` to this contract.
