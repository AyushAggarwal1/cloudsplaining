# Identity Classification Robustness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Identity inventory classification never silently guesses: a shared evidence-precedence resolver yields `human` / `machine` / `unknown` plus a `classification_reason` on every record, with AWS gaining live gap-user credential lookups and CloudTrail credential events.

**Architecture:** `model.py` gains `UNKNOWN` and `classification_reason`; `classify.py` gains a first-signal-wins `resolve()` plus a `machine_name_signal()` (tokens + workload email domains). Each cloud builder (`aws`, `azure`, `gcp`, `oci`) maps its native evidence into ordered signals — hard structure → machine-name → credential/activity shape → unknown. `command/download.py` adds three enrichments to the snapshot: `credentialReportGeneratedTime`, two extra CloudTrail event names, and a `credentialSupplement` from per-user IAM calls for users missing from the cached credential report.

**Tech Stack:** Python 3.10+, dataclasses, `schema` (input validation), moto + unittest for tests, uv + just for tooling.

**Spec:** `docs/identity-classification-design.md` (approved 2026-08-02).

## Global Constraints

- Run every Python command through uv with the frozen lockfile: `UV_FROZEN=1 uv run pytest …` (repo rule).
- TDD: each task writes its failing test before implementation (repo rule: no production code without a failing test first).
- **Commit gating:** repo owner requires explicit approval for every `git commit`. If blanket approval for this plan has not been given, SKIP the commit steps and leave changes staged-ready; the session lead collects approval at the end.
- Never touch `.live-scans/`, `iam-*-default.json`, `default.json`, `iam-report-default.html` (untracked live data — never `git add`).
- `just lint` currently has ~47 pre-existing ruff errors in `cloudsplaining/multicloud/` — those are baseline, not this change's fault; new files must still pass.
- Classification string constants are a documented vocabulary — copy reason strings **verbatim** from this plan; tests assert on them.
- Prefer membership assertions over exact-list assertions (repo rule).

---

### Task 1: `UNKNOWN` classification + `classification_reason` on the shared model

**Files:**
- Modify: `cloudsplaining/identity_inventory/model.py`
- Test: `test/identity_inventory/test_model.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: `UNKNOWN: str = "unknown"` constant; `IdentityRecord.classification_reason: str | None = None` field; `to_dict()` output gains key `"classification_reason"` immediately after `"classification"`.

- [ ] **Step 1: Write the failing test**

Append to `test/identity_inventory/test_model.py`:

```python
class TestClassificationReason(unittest.TestCase):
    def test_unknown_constant_exists(self):
        from cloudsplaining.identity_inventory.model import UNKNOWN

        self.assertEqual(UNKNOWN, "unknown")

    def test_classification_reason_defaults_to_none_and_serializes(self):
        record = IdentityRecord(
            provider="aws", identity_type="user", id="arn:x", name="x", classification="human"
        )
        self.assertIsNone(record.classification_reason)
        self.assertIn("classification_reason", record.to_dict())

    def test_classification_reason_round_trips(self):
        record = IdentityRecord(
            provider="aws",
            identity_type="user",
            id="arn:x",
            name="x",
            classification="unknown",
            classification_reason="no credential evidence: credential report unavailable",
        )
        data = record.to_dict()
        self.assertEqual(data["classification"], "unknown")
        self.assertEqual(
            data["classification_reason"], "no credential evidence: credential report unavailable"
        )
```

(Match the file's existing imports; it already imports `IdentityRecord` and `unittest`.)

- [ ] **Step 2: Run test to verify it fails**

Run: `UV_FROZEN=1 uv run pytest test/identity_inventory/test_model.py -q`
Expected: FAIL — `ImportError: cannot import name 'UNKNOWN'` (and/or `TypeError: unexpected keyword argument 'classification_reason'`).

- [ ] **Step 3: Write minimal implementation**

In `cloudsplaining/identity_inventory/model.py`:

```python
HUMAN = "human"
MACHINE = "machine"
UNKNOWN = "unknown"
```

Add the field directly after `classification` (it has a default, so it may legally precede the other defaulted fields):

```python
    classification: str  # HUMAN | MACHINE | UNKNOWN
    classification_reason: str | None = None
```

In `to_dict()` add right after the `"classification"` entry:

```python
            "classification": self.classification,
            "classification_reason": self.classification_reason,
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `UV_FROZEN=1 uv run pytest test/identity_inventory/test_model.py -q`
Expected: PASS (all).

- [ ] **Step 5: Commit (if approved)**

```bash
git add cloudsplaining/identity_inventory/model.py test/identity_inventory/test_model.py
git commit -m "feat: identity_inventory: UNKNOWN classification and classification_reason field"
```

---

### Task 2: shared resolver + machine-name signal + new tokens/domains

**Files:**
- Modify: `cloudsplaining/identity_inventory/classify.py`
- Test: `test/identity_inventory/test_classify.py`

**Interfaces:**
- Consumes: `MACHINE`, `UNKNOWN` from `model.py` (Task 1).
- Produces:
  - `resolve(*signals: tuple[str, str] | None, fallback: str) -> tuple[str, str]` — first non-None signal wins; else `(UNKNOWN, fallback)`.
  - `machine_name_signal(*names: str | None) -> tuple[str, str] | None` — token match → `(MACHINE, f"automation-style name (token: {token})")`; workload email domain → `(MACHINE, f"workload email domain ({suffix})")`; else None.
  - `MACHINE_DOMAIN_SUFFIXES = ("gserviceaccount.com",)`.
  - `is_machine_name` unchanged (token-only, kept for compatibility).
  - New tokens in `MACHINE_NAME_TOKENS`: `ciem`, `cspm`, `cnapp`, `siem`, `collector`, `exporter`, `ingest`, `devops`, `noreply`, `smtp`.

- [ ] **Step 1: Write the failing test**

Append to `test/identity_inventory/test_classify.py`:

```python
from cloudsplaining.identity_inventory.classify import machine_name_signal, resolve
from cloudsplaining.identity_inventory.model import HUMAN, MACHINE, UNKNOWN


class TestResolve(unittest.TestCase):
    def test_first_present_signal_wins(self):
        self.assertEqual(
            resolve(None, (MACHINE, "automation-style name (token: svc)"), (HUMAN, "x"), fallback="f"),
            (MACHINE, "automation-style name (token: svc)"),
        )

    def test_no_signals_yields_unknown_with_fallback_reason(self):
        self.assertEqual(resolve(None, None, fallback="no evidence"), (UNKNOWN, "no evidence"))


class TestMachineNameSignal(unittest.TestCase):
    def test_new_tokens_match_whole_word(self):
        for name in ("ciem", "cspm-scanner", "acme-cnapp", "siem_forwarder", "devops.alerts@corp.com",
                     "noreply@corp.com", "ses-smtp-user.20221228", "log-collector", "node-exporter-1",
                     "data-ingest"):
            self.assertIsNotNone(machine_name_signal(name), name)

    def test_token_reported_in_reason(self):
        self.assertEqual(machine_name_signal("ciem"), (MACHINE, "automation-style name (token: ciem)"))

    def test_tokens_do_not_match_inside_words(self):
        for name in ("lucia", "concierge", "smithy"):  # ci/ciem/smtp must not fire mid-word
            self.assertIsNone(machine_name_signal(name), name)

    def test_workload_email_domain(self):
        self.assertEqual(
            machine_name_signal("sa-123@my-project.iam.gserviceaccount.com"),
            (MACHINE, "workload email domain (gserviceaccount.com)"),
        )

    def test_none_and_empty_names_are_skipped(self):
        self.assertIsNone(machine_name_signal(None, ""))

    def test_first_matching_name_wins(self):
        self.assertEqual(
            machine_name_signal("Friendly Name", "svc-deployer"),
            (MACHINE, "automation-style name (token: svc)"),
        )
```

(Reuse the file's existing `unittest` import; add the new imports at top with the existing ones.)

- [ ] **Step 2: Run test to verify it fails**

Run: `UV_FROZEN=1 uv run pytest test/identity_inventory/test_classify.py -q`
Expected: FAIL — `ImportError: cannot import name 'resolve'`.

- [ ] **Step 3: Write minimal implementation**

In `cloudsplaining/identity_inventory/classify.py`:

1. Add to `MACHINE_NAME_TOKENS` (keep alphabetical order): `"ciem"`, `"cnapp"`, `"collector"`, `"cspm"`, `"devops"`, `"exporter"`, `"ingest"`, `"noreply"`, `"siem"`, `"smtp"`.
2. Give the token pattern a named group:

```python
_TOKEN_PATTERN = re.compile(r"(?:^|[-_.])(?P<token>" + "|".join(MACHINE_NAME_TOKENS) + r")(?:$|[-_.0-9])")
```

3. Add below `is_machine_name` (which stays as-is):

```python
from cloudsplaining.identity_inventory.model import MACHINE, UNKNOWN

#: Email domains that only workloads use; a user-shaped identity with one is a machine.
MACHINE_DOMAIN_SUFFIXES = ("gserviceaccount.com",)


def machine_name_signal(*names: str | None) -> tuple[str, str] | None:
    """A (MACHINE, reason) signal when any name looks like automation, else ``None``.

    Checks the token heuristic on the email local part, then workload email domains.
    """
    for name in names:
        if not name:
            continue
        lowered = name.lower()
        match = _TOKEN_PATTERN.search(lowered.split("@", 1)[0])
        if match:
            return (MACHINE, f"automation-style name (token: {match.group('token')})")
        domain = lowered.rsplit("@", 1)[-1] if "@" in lowered else ""
        for suffix in MACHINE_DOMAIN_SUFFIXES:
            if domain == suffix or domain.endswith("." + suffix):
                return (MACHINE, f"workload email domain ({suffix})")
    return None


def resolve(*signals: tuple[str, str] | None, fallback: str) -> tuple[str, str]:
    """First present (classification, reason) signal wins; no signals → UNKNOWN."""
    for signal in signals:
        if signal is not None:
            return signal
    return (UNKNOWN, fallback)
```

(The `model` import creates no cycle: `model.py` imports only `parsing`.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `UV_FROZEN=1 uv run pytest test/identity_inventory/test_classify.py -q`
Expected: PASS. Also run `UV_FROZEN=1 uv run pytest test/identity_inventory/ -q` — the new tokens must not break existing name tests; if an existing fixture name (e.g. containing `devops`/`smtp`) now classifies machine, update that test's fixture name to stay neutral, preserving its original intent.

- [ ] **Step 5: Commit (if approved)**

```bash
git add cloudsplaining/identity_inventory/classify.py test/identity_inventory/test_classify.py
git commit -m "feat: identity_inventory: shared signal resolver, workload domains, new name tokens"
```

---

### Task 3: AWS classification through the resolver (report-shape signals, reasons, honest fallbacks)

**Files:**
- Modify: `cloudsplaining/identity_inventory/aws.py`
- Test: `test/identity_inventory/test_aws.py`

**Interfaces:**
- Consumes: `resolve`, `machine_name_signal` (Task 2); `UNKNOWN`, `classification_reason` (Task 1).
- Produces (aws.py internals used by Task 4):
  - `_shape_signal(shape: dict[str, Any] | None, source: str) -> tuple[str, str] | None` with `shape = {"has_password": bool, "has_mfa": bool, "active_keys": int}`; human reason `f"console password or MFA ({source})"`, machine reason `f"active access keys, no console password ({source})"`, zero-credential → `(UNKNOWN, f"no credentials provisioned ({source})")`.
  - `_report_shape(report_row: dict | None) -> dict | None`.
  - `_user_classification(name, report_row, report_available) -> tuple[str, str]` (Task 4 extends the signature).
  - Reason vocabulary produced here: `"AWS service role"`, `"SAML-federated role"`, `"workload role"`, `"access key"`, fallbacks `"no credential evidence: credential report unavailable"` and `"created after credential report was generated"`.

- [ ] **Step 1: Write the failing test**

Append to `test/identity_inventory/test_aws.py` (reuse its `_authz_details()` fixture builder and `_by_name` helper if present; otherwise index records by name as the file already does):

```python
class TestClassificationReasons(unittest.TestCase):
    def _records(self, data):
        return {record.name: record for record in build_inventory(data)}

    def test_neutral_user_without_any_credential_report_is_unknown(self):
        data = _authz_details()  # fixture has no credentialReport key
        records = self._records(data)
        neutral = records["alice"]  # the fixture's neutral-named user
        self.assertEqual(neutral.classification, "unknown")
        self.assertEqual(
            neutral.classification_reason, "no credential evidence: credential report unavailable"
        )

    def test_user_missing_from_present_report_is_unknown_with_race_reason(self):
        data = _authz_details()
        data["credentialReport"] = (
            "user,arn,password_enabled,mfa_active,access_key_1_active,access_key_1_last_rotated,"
            "access_key_2_active,access_key_2_last_rotated,password_last_used,"
            "access_key_1_last_used_date,access_key_2_last_used_date\n"
            "someoneelse,arn:aws:iam::111122223333:user/someoneelse,true,false,false,N/A,false,N/A,N/A,N/A,N/A\n"
        )
        records = self._records(data)
        neutral = records["alice"]
        self.assertEqual(neutral.classification, "unknown")
        self.assertEqual(neutral.classification_reason, "created after credential report was generated")

    def test_password_user_is_human_with_report_reason(self):
        data = _authz_details()
        data["credentialReport"] = (
            "user,arn,password_enabled,mfa_active,access_key_1_active,access_key_1_last_rotated,"
            "access_key_2_active,access_key_2_last_rotated,password_last_used,"
            "access_key_1_last_used_date,access_key_2_last_used_date\n"
            "alice,arn:aws:iam::111122223333:user/alice,true,false,false,N/A,false,N/A,N/A,N/A,N/A\n"
        )
        alice = self._records(data)["alice"]
        self.assertEqual(alice.classification, "human")
        self.assertEqual(alice.classification_reason, "console password or MFA (credential report)")

    def test_keys_only_user_is_machine_with_report_reason(self):
        data = _authz_details()
        data["credentialReport"] = (
            "user,arn,password_enabled,mfa_active,access_key_1_active,access_key_1_last_rotated,"
            "access_key_2_active,access_key_2_last_rotated,password_last_used,"
            "access_key_1_last_used_date,access_key_2_last_used_date\n"
            "alice,arn:aws:iam::111122223333:user/alice,false,false,true,2026-01-01T00:00:00+00:00,false,N/A,N/A,N/A,N/A\n"
        )
        alice = self._records(data)["alice"]
        self.assertEqual(alice.classification, "machine")
        self.assertEqual(
            alice.classification_reason, "active access keys, no console password (credential report)"
        )

    def test_zero_credential_row_is_unknown(self):
        data = _authz_details()
        data["credentialReport"] = (
            "user,arn,password_enabled,mfa_active,access_key_1_active,access_key_1_last_rotated,"
            "access_key_2_active,access_key_2_last_rotated,password_last_used,"
            "access_key_1_last_used_date,access_key_2_last_used_date\n"
            "alice,arn:aws:iam::111122223333:user/alice,false,false,false,N/A,false,N/A,N/A,N/A,N/A\n"
        )
        alice = self._records(data)["alice"]
        self.assertEqual(alice.classification, "unknown")
        self.assertEqual(alice.classification_reason, "no credentials provisioned (credential report)")

    def test_machine_named_user_reason(self):
        data = _authz_details()  # fixture already contains svc-terraform
        record = self._records(data)["svc-terraform"]
        self.assertEqual(record.classification, "machine")
        self.assertEqual(record.classification_reason, "automation-style name (token: svc)")

    def test_role_and_access_key_reasons(self):
        data = _authz_details()
        data["credentialReport"] = (
            "user,arn,password_enabled,mfa_active,access_key_1_active,access_key_1_last_rotated,"
            "access_key_2_active,access_key_2_last_rotated,password_last_used,"
            "access_key_1_last_used_date,access_key_2_last_used_date\n"
            "alice,arn:aws:iam::111122223333:user/alice,false,false,true,2026-01-01T00:00:00+00:00,false,N/A,N/A,N/A,N/A\n"
        )
        records = self._records(data)
        reasons = {record.classification_reason for record in records.values()}
        self.assertIn("access key", reasons)           # alice/access-key-1 child record
        self.assertIn("SAML-federated role", reasons)  # sso-developer
        self.assertIn("workload role", reasons)        # app-server-role
        self.assertIn("AWS service role", reasons)     # AWSServiceRoleForSupport
```

Fixture names verified against the current `_authz_details()`: `alice` (neutral), `svc-terraform` (token name), roles `app-server-role` / `sso-developer` / `AWSServiceRoleForSupport`, helper `_by_name` — all already exist.

- [ ] **Step 2: Run test to verify it fails**

Run: `UV_FROZEN=1 uv run pytest test/identity_inventory/test_aws.py -q`
Expected: FAIL — reasons are `None` and no-report users classify `human` today.

- [ ] **Step 3: Write minimal implementation**

In `cloudsplaining/identity_inventory/aws.py`:

```python
from cloudsplaining.identity_inventory.classify import machine_name_signal, resolve
from cloudsplaining.identity_inventory.model import HUMAN, MACHINE, UNKNOWN, IdentityRecord
```

Replace `_is_machine_user` with signal helpers:

```python
def _report_shape(report_row: dict[str, Any] | None) -> dict[str, Any] | None:
    if report_row is None:
        return None
    active_keys = sum(
        1 for slot in (1, 2) if _report_flag(report_row, f"access_key_{slot}_active")
    )
    return {
        "has_password": _report_flag(report_row, "password_enabled"),
        "has_mfa": _report_flag(report_row, "mfa_active"),
        "active_keys": active_keys,
    }


def _shape_signal(shape: dict[str, Any] | None, source: str) -> tuple[str, str] | None:
    """Classify a credential shape: password/MFA → human, keys-only → machine, nothing → unknown."""
    if shape is None:
        return None
    if shape["has_password"] or shape["has_mfa"]:
        return (HUMAN, f"console password or MFA ({source})")
    if shape["active_keys"]:
        return (MACHINE, f"active access keys, no console password ({source})")
    return (UNKNOWN, f"no credentials provisioned ({source})")


def _user_classification(
    name: str, report_row: dict[str, Any] | None, report_available: bool
) -> tuple[str, str]:
    fallback = (
        "created after credential report was generated"
        if report_available
        else "no credential evidence: credential report unavailable"
    )
    return resolve(
        machine_name_signal(name),
        _shape_signal(_report_shape(report_row), "credential report"),
        fallback=fallback,
    )
```

Wire `_user_record` (signature gains `report_available: bool`):

```python
    classification, reason = _user_classification(name, report_row, report_available)
    return IdentityRecord(
        ...,
        classification=classification,
        classification_reason=reason,
        ...,
    )
```

`build_inventory` passes `report_available=bool(data.get("credentialReport"))`. Roles: in `_role_record`, compute:

```python
    if _is_service_role(role):
        classification, reason = MACHINE, "AWS service role"
    elif _is_sso_role(role):
        classification, reason = HUMAN, "SAML-federated role"
    else:
        classification, reason = MACHINE, "workload role"
```

where `_is_service_role(role)` extracts the existing `/aws-service-role/` path check out of `_is_sso_role` (keep `_is_sso_role`'s SAML logic; it no longer needs the path check but keeping it is harmless — move it for clarity). Access-key records get `classification_reason="access key"`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `UV_FROZEN=1 uv run pytest test/identity_inventory/test_aws.py -q`
Expected: PASS. Existing assertions about `classification` (e.g. keys-only machine users) must still hold; fix any fixture-name collisions with the new tokens rather than weakening assertions.

- [ ] **Step 5: Commit (if approved)**

```bash
git add cloudsplaining/identity_inventory/aws.py test/identity_inventory/test_aws.py
git commit -m "feat: identity_inventory(aws): resolver-based classification with reasons and honest unknowns"
```

---

### Task 4: AWS gap-user evidence — credentialSupplement + CloudTrail credential events (the ciem fix)

**Files:**
- Modify: `cloudsplaining/identity_inventory/aws.py`
- Test: `test/identity_inventory/test_aws.py`

**Interfaces:**
- Consumes: Task 3's `_shape_signal` / `_user_classification`; snapshot keys produced by Task 5 (`credentialSupplement`, extended `cloudTrailEvents`) — builders only read dicts, so this task is testable without Task 5.
- Produces:
  - `_supplement_shape(row: dict | None) -> dict | None` — requires `has_login_profile` **and** `access_keys_active` present, else None; maps to the Task 3 shape dict (`has_mfa` = `mfa_devices > 0`, default 0).
  - `_credential_event_flags(events: list[dict]) -> dict[str, dict[str, bool]]` — per user: `access_key_created` / `login_profile_created` from `CreateAccessKey` / `CreateLoginProfile` events (`requestParameters.userName`, falling back to `responseElements.accessKey.userName` for CreateAccessKey).
  - `_events_signal(flags: dict | None) -> tuple[str, str] | None` — login profile → `(HUMAN, "console login profile created (CloudTrail events)")`; access key only → `(MACHINE, "access key created, no console password (CloudTrail events)")`; else None.
  - `_user_classification(name, report_row, report_available, supplement_row, event_flags)` — final signature; precedence: name → supplement → report → events → fallback.

- [ ] **Step 1: Write the failing test**

Append to `test/identity_inventory/test_aws.py`:

```python
def _create_event(event_name, user_name):
    return {
        "CloudTrailEvent": json.dumps(
            {
                "eventName": event_name,
                "userIdentity": {"arn": "arn:aws:iam::111122223333:user/creator"},
                "requestParameters": {"userName": user_name},
            }
        )
    }


class TestGapUserEvidence(unittest.TestCase):
    """The ciem scenario: user created after the cached credential report was generated."""

    def _records(self, data):
        return {record.name: record for record in build_inventory(data)}

    def _gap_data(self):
        data = _authz_details()
        data["credentialReport"] = (
            "user,arn,password_enabled,mfa_active,access_key_1_active,access_key_1_last_rotated,"
            "access_key_2_active,access_key_2_last_rotated,password_last_used,"
            "access_key_1_last_used_date,access_key_2_last_used_date\n"
            "someoneelse,arn:aws:iam::111122223333:user/someoneelse,true,false,false,N/A,false,N/A,N/A,N/A,N/A\n"
        )
        return data

    def test_gap_user_with_access_key_event_is_machine(self):
        data = self._gap_data()
        data["cloudTrailEvents"] = [_create_event("CreateAccessKey", "alice")]
        alice = self._records(data)["alice"]
        self.assertEqual(alice.classification, "machine")
        self.assertEqual(
            alice.classification_reason, "access key created, no console password (CloudTrail events)"
        )

    def test_gap_user_with_login_profile_event_is_human_even_with_key_event(self):
        data = self._gap_data()
        data["cloudTrailEvents"] = [
            _create_event("CreateAccessKey", "alice"),
            _create_event("CreateLoginProfile", "alice"),
        ]
        alice = self._records(data)["alice"]
        self.assertEqual(alice.classification, "human")
        self.assertEqual(
            alice.classification_reason, "console login profile created (CloudTrail events)"
        )

    def test_supplement_beats_events_and_stale_report(self):
        data = self._gap_data()
        data["cloudTrailEvents"] = [_create_event("CreateAccessKey", "alice")]
        data["credentialSupplement"] = {
            "alice": {
                "access_keys_active": 0,
                "has_login_profile": True,
                "mfa_devices": 0,
                "checked_at": "2026-08-02T15:00:00+00:00",
            }
        }
        alice = self._records(data)["alice"]
        self.assertEqual(alice.classification, "human")
        self.assertEqual(alice.classification_reason, "console password or MFA (live IAM lookup)")

    def test_supplement_keys_only_is_machine(self):
        data = self._gap_data()
        data["credentialSupplement"] = {
            "alice": {"access_keys_active": 2, "has_login_profile": False, "mfa_devices": 0}
        }
        alice = self._records(data)["alice"]
        self.assertEqual(alice.classification, "machine")
        self.assertEqual(
            alice.classification_reason, "active access keys, no console password (live IAM lookup)"
        )

    def test_partial_supplement_row_is_ignored(self):
        data = self._gap_data()
        data["credentialSupplement"] = {"alice": {"mfa_devices": 0}}  # both required keys absent
        alice = self._records(data)["alice"]
        self.assertEqual(alice.classification, "unknown")
        self.assertEqual(alice.classification_reason, "created after credential report was generated")

    def test_gap_user_with_no_evidence_is_unknown(self):
        alice = self._records(self._gap_data())["alice"]
        self.assertEqual(alice.classification, "unknown")
        self.assertEqual(alice.classification_reason, "created after credential report was generated")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `UV_FROZEN=1 uv run pytest test/identity_inventory/test_aws.py::TestGapUserEvidence -q`
Expected: FAIL — supplement/events are not consumed yet (everything resolves unknown or errors on signature).

- [ ] **Step 3: Write minimal implementation**

In `cloudsplaining/identity_inventory/aws.py`:

```python
_CREDENTIAL_EVENT_NAMES = ("CreateAccessKey", "CreateLoginProfile")


def _supplement_shape(row: dict[str, Any] | None) -> dict[str, Any] | None:
    """Shape from a live-lookup supplement row; needs both authoritative fields."""
    if not row or "has_login_profile" not in row or "access_keys_active" not in row:
        return None
    return {
        "has_password": bool(row["has_login_profile"]),
        "has_mfa": bool(row.get("mfa_devices") or 0),
        "active_keys": int(row["access_keys_active"] or 0),
    }


def _credential_event_flags(events: list[dict[str, Any]]) -> dict[str, dict[str, bool]]:
    """Map user name -> which credential-creation events CloudTrail saw for them."""
    flags: dict[str, dict[str, bool]] = {}
    for item in events:
        event = _event_payload(item)
        if event is None:
            continue
        event_name = event.get("eventName") or event.get("EventName")
        if event_name not in _CREDENTIAL_EVENT_NAMES:
            continue
        parameters = event.get("requestParameters") or {}
        response = event.get("responseElements") or {}
        user = parameters.get("userName") or (response.get("accessKey") or {}).get("userName")
        if not user:
            continue
        key = "access_key_created" if event_name == "CreateAccessKey" else "login_profile_created"
        flags.setdefault(user, {})[key] = True
    return flags


def _events_signal(flags: dict[str, bool] | None) -> tuple[str, str] | None:
    if not flags:
        return None
    if flags.get("login_profile_created"):
        return (HUMAN, "console login profile created (CloudTrail events)")
    if flags.get("access_key_created"):
        return (MACHINE, "access key created, no console password (CloudTrail events)")
    return None
```

Extend `_user_classification`:

```python
def _user_classification(
    name: str,
    report_row: dict[str, Any] | None,
    report_available: bool,
    supplement_row: dict[str, Any] | None,
    event_flags: dict[str, bool] | None,
) -> tuple[str, str]:
    fallback = (
        "created after credential report was generated"
        if report_available
        else "no credential evidence: credential report unavailable"
    )
    return resolve(
        machine_name_signal(name),
        _shape_signal(_supplement_shape(supplement_row), "live IAM lookup"),
        _shape_signal(_report_shape(report_row), "credential report"),
        _events_signal(event_flags),
        fallback=fallback,
    )
```

`build_inventory` computes once and threads through `_user_record`:

```python
    supplement = data.get("credentialSupplement") or {}
    credential_events = _credential_event_flags(data.get("cloudTrailEvents") or [])
```

(`_user_record` looks up `supplement.get(name)` and `credential_events.get(name)`.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `UV_FROZEN=1 uv run pytest test/identity_inventory/test_aws.py -q`
Expected: PASS (all, including Task 3's).

- [ ] **Step 5: Commit (if approved)**

```bash
git add cloudsplaining/identity_inventory/aws.py test/identity_inventory/test_aws.py
git commit -m "feat: identity_inventory(aws): classify report-gap users from live supplement and CloudTrail credential events"
```

---

### Task 5: download enrichment — GeneratedTime, credential supplement, extra event names, schema keys

**Files:**
- Modify: `cloudsplaining/command/download.py`
- Modify: `cloudsplaining/shared/validation.py`
- Test: `test/command/test_download.py`

**Interfaces:**
- Consumes: nothing from other tasks (builder consumption was Task 4).
- Produces snapshot keys read by Task 4 and validated by scan:
  - `get_credential_report(iam_client, ...) -> tuple[str, str | None] | None` — now returns `(csv_text, generated_time_iso_or_None)`; `None` on denial as before.
  - `CLOUDTRAIL_CREATE_EVENT_NAMES = ("CreateUser", "CreateRole", "CreateAccessKey", "CreateLoginProfile")`.
  - `users_missing_from_report(user_detail_list: list[dict], report_text: str) -> list[str]`.
  - `get_credential_supplement(iam_client, user_names: list[str]) -> dict[str, dict[str, Any]]` with per-user `{"access_keys_active": int, "has_login_profile": bool, "mfa_devices": int, "checked_at": iso}`; per-call best-effort (a denied call omits its keys); capped at `CREDENTIAL_SUPPLEMENT_CAP = 50` with a warning.
  - Snapshot gains `credentialReportGeneratedTime: str` and `credentialSupplement: dict` (only when a report exists and users are missing from it).
  - `AUTHORIZATION_DETAILS_SCHEMA` accepts both new keys (strict schema would otherwise reject fresh downloads at scan time).

- [ ] **Step 1: Write the failing tests**

Append to `test/command/test_download.py` (moto's `@mock_aws` and existing stubs are already in this file):

```python
@mock_aws
class TestCredentialSupplement(unittest.TestCase):
    def test_supplement_shapes_users(self):
        client = boto3.client("iam", region_name="us-east-1")
        client.create_user(UserName="machine-ish")
        client.create_access_key(UserName="machine-ish")
        client.create_user(UserName="human-ish")
        client.create_login_profile(UserName="human-ish", Password="Xx1234567890!aB")
        supplement = get_credential_supplement(client, ["machine-ish", "human-ish"])
        self.assertEqual(supplement["machine-ish"]["access_keys_active"], 1)
        self.assertFalse(supplement["machine-ish"]["has_login_profile"])
        self.assertTrue(supplement["human-ish"]["has_login_profile"])
        self.assertIn("checked_at", supplement["human-ish"])

    def test_missing_users_diff(self):
        users = [{"UserName": "a"}, {"UserName": "b"}]
        report = "user,arn\na,arn:aws:iam::111122223333:user/a\n"
        self.assertEqual(users_missing_from_report(users, report), ["b"])

    def test_denied_calls_omit_keys_but_do_not_raise(self):
        supplement = get_credential_supplement(_DeniedSupplementClient(), ["x"])
        self.assertEqual(list(supplement), ["x"])
        self.assertNotIn("access_keys_active", supplement["x"])


class _DeniedSupplementClient:
    def _deny(self, operation):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "nope"}}, operation)

    def list_access_keys(self, UserName):  # noqa: N803 - boto3 casing
        self._deny("ListAccessKeys")

    def get_login_profile(self, UserName):  # noqa: N803 - boto3 casing
        self._deny("GetLoginProfile")

    def list_mfa_devices(self, UserName):  # noqa: N803 - boto3 casing
        self._deny("ListMFADevices")
```

Also update the existing `TestGetCredentialReport` expectations for the new tuple return:

```python
    def test_returns_csv_text_and_generated_time(self):
        client = boto3.client("iam", region_name="us-east-1")
        report, generated_time = get_credential_report(client)
        self.assertIn("user", report)
        # moto reports a generation time; live AWS always sets one.
        self.assertTrue(generated_time is None or isinstance(generated_time, str))
```

And the event-name constant:

```python
    def test_event_names_include_credential_events(self):
        from cloudsplaining.command.download import CLOUDTRAIL_CREATE_EVENT_NAMES

        self.assertIn("CreateAccessKey", CLOUDTRAIL_CREATE_EVENT_NAMES)
        self.assertIn("CreateLoginProfile", CLOUDTRAIL_CREATE_EVENT_NAMES)
```

Schema acceptance — append to `test/identity_inventory/test_scan_integration.py`'s existing test data the two new keys (`"credentialReportGeneratedTime": "2026-08-02T10:00:00+00:00"`, `"credentialSupplement": {}`) so the scan-path validation exercises them (Task 9 runs it).

- [ ] **Step 2: Run tests to verify they fail**

Run: `UV_FROZEN=1 uv run pytest test/command/test_download.py -q`
Expected: FAIL — `ImportError: cannot import name 'get_credential_supplement'` / tuple-unpack errors.

- [ ] **Step 3: Write minimal implementation**

In `cloudsplaining/command/download.py`:

```python
CLOUDTRAIL_CREATE_EVENT_NAMES = ("CreateUser", "CreateRole", "CreateAccessKey", "CreateLoginProfile")

#: Ceiling on per-user supplement lookups; the report gap is normally 0–2 users.
CREDENTIAL_SUPPLEMENT_CAP = 50
```

`get_credential_report` returns the tuple (docstring updated; denial path unchanged → `None`):

```python
        response = iam_client.get_credential_report()
        content = response["Content"]
        generated = response.get("GeneratedTime")
        text = content.decode("utf-8") if isinstance(content, bytes) else str(content)
        return text, (generated.isoformat() if hasattr(generated, "isoformat") else generated)
```

New helpers:

```python
def users_missing_from_report(user_detail_list: list[dict[str, Any]], report_text: str) -> list[str]:
    """User names present in the authorization details but absent from the credential report."""
    reported = {row.get("user") for row in csv.DictReader(io.StringIO(report_text))}
    return [
        name
        for user in user_detail_list
        if (name := user.get("UserName")) and name not in reported
    ]


def get_credential_supplement(iam_client: IAMClient, user_names: list[str]) -> dict[str, dict[str, Any]]:
    """Live credential shape for users the cached report predates. Best-effort per call:
    a denied call omits its keys; classification treats partial rows as no evidence."""
    if len(user_names) > CREDENTIAL_SUPPLEMENT_CAP:
        logger.warning(
            "Credential supplement capped at %s of %s users missing from the report.",
            CREDENTIAL_SUPPLEMENT_CAP,
            len(user_names),
        )
        user_names = user_names[:CREDENTIAL_SUPPLEMENT_CAP]
    supplement: dict[str, dict[str, Any]] = {}
    for name in user_names:
        row: dict[str, Any] = {"checked_at": datetime.now(timezone.utc).isoformat()}
        try:
            keys = iam_client.list_access_keys(UserName=name)["AccessKeyMetadata"]
            row["access_keys_active"] = sum(1 for key in keys if key.get("Status") == "Active")
        except ClientError as error:
            logger.warning("Supplement list_access_keys(%s): %s", name, error)
        try:
            iam_client.get_login_profile(UserName=name)
            row["has_login_profile"] = True
        except ClientError as error:
            if error.response.get("Error", {}).get("Code") in ("NoSuchEntity", "NoSuchEntityException"):
                row["has_login_profile"] = False
            else:
                logger.warning("Supplement get_login_profile(%s): %s", name, error)
        try:
            row["mfa_devices"] = len(iam_client.list_mfa_devices(UserName=name)["MFADevices"])
        except ClientError as error:
            logger.warning("Supplement list_mfa_devices(%s): %s", name, error)
        supplement[name] = row
    return supplement
```

(Imports: `from datetime import datetime, timezone` — check what the module already imports.) Wire into `download()`:

```python
    if not skip_credential_report:
        report = get_credential_report(_iam_client(session_data))
        if report is not None:
            report_text, generated_time = report
            results["credentialReport"] = report_text
            if generated_time:
                results["credentialReportGeneratedTime"] = generated_time
            missing = users_missing_from_report(results.get("UserDetailList") or [], report_text)
            if missing:
                results["credentialSupplement"] = get_credential_supplement(
                    _iam_client(session_data), missing
                )
```

In `cloudsplaining/shared/validation.py`, extend `AUTHORIZATION_DETAILS_SCHEMA`:

```python
        Optional("credentialReport"): object,
        Optional("credentialReportGeneratedTime"): object,
        Optional("credentialSupplement"): object,
        Optional("cloudTrailEvents"): [object],
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `UV_FROZEN=1 uv run pytest test/command/test_download.py -q`
Expected: PASS (all — including pre-existing download tests updated for the tuple return).

- [ ] **Step 5: Commit (if approved)**

```bash
git add cloudsplaining/command/download.py cloudsplaining/shared/validation.py test/command/test_download.py test/identity_inventory/test_scan_integration.py
git commit -m "feat: download: credential-report GeneratedTime, gap-user credential supplement, credential CloudTrail events"
```

---

### Task 6: Azure — sign-in-shape classification with availability gate

**Files:**
- Modify: `cloudsplaining/identity_inventory/azure.py`
- Test: `test/identity_inventory/test_azure.py`

**Interfaces:**
- Consumes: `resolve`, `machine_name_signal` (Task 2); `UNKNOWN` (Task 1).
- Produces (azure.py internals): `_sign_in_available(users: list[dict]) -> bool`; `_user_classification(user: dict, sign_in_available: bool) -> tuple[str, str]`. Reasons: `"directory synchronization account"`, `"interactive sign-ins"`, `"non-interactive sign-ins only"`, `"never signed in"`, `"Entra user (sign-in data unavailable)"`, `"service principal"`.

- [ ] **Step 1: Write the failing test**

Append to `test/identity_inventory/test_azure.py` (mirror its existing snapshot-builder style):

```python
class TestAzureClassificationSignals(unittest.TestCase):
    def _user(self, **overrides):
        user = {"id": "u1", "userPrincipalName": "pat@corp.com", "displayName": "Pat"}
        user.update(overrides)
        return user

    def _record(self, user, others=()):
        data = {"users": [user, *others], "servicePrincipals": []}
        return next(r for r in build_inventory(data) if r.id == user["id"])

    def test_interactive_sign_in_is_human(self):
        record = self._record(
            self._user(signInActivity={"lastSignInDateTime": "2026-07-01T00:00:00Z"})
        )
        self.assertEqual(record.classification, "human")
        self.assertEqual(record.classification_reason, "interactive sign-ins")

    def test_non_interactive_only_is_machine(self):
        record = self._record(
            self._user(signInActivity={"lastNonInteractiveSignInDateTime": "2026-07-01T00:00:00Z"})
        )
        self.assertEqual(record.classification, "machine")
        self.assertEqual(record.classification_reason, "non-interactive sign-ins only")

    def test_never_signed_in_is_unknown_when_data_available(self):
        other = {"id": "u2", "userPrincipalName": "x@corp.com",
                 "signInActivity": {"lastSignInDateTime": "2026-07-01T00:00:00Z"}}
        record = self._record(self._user(), others=[other])
        self.assertEqual(record.classification, "unknown")
        self.assertEqual(record.classification_reason, "never signed in")

    def test_soft_human_default_when_sign_in_data_unavailable(self):
        record = self._record(self._user())
        self.assertEqual(record.classification, "human")
        self.assertEqual(record.classification_reason, "Entra user (sign-in data unavailable)")

    def test_sync_account_is_machine(self):
        record = self._record(
            self._user(
                userPrincipalName="Sync_AAD1@corp.onmicrosoft.com",
                displayName="On-Premises Directory Synchronization Service Account",
            )
        )
        self.assertEqual(record.classification, "machine")
        self.assertEqual(record.classification_reason, "directory synchronization account")

    def test_service_principal_reason(self):
        data = {"users": [], "servicePrincipals": [{"id": "sp1", "displayName": "neutral-app"}]}
        record = build_inventory(data)[0]
        self.assertEqual(record.classification, "machine")
        self.assertEqual(record.classification_reason, "service principal")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `UV_FROZEN=1 uv run pytest test/identity_inventory/test_azure.py -q`
Expected: FAIL — reasons are None, never-signed-in users classify human today.

- [ ] **Step 3: Write minimal implementation**

In `cloudsplaining/identity_inventory/azure.py`:

```python
_SYNC_UPN_PREFIX = "sync_"
_SYNC_DISPLAY_NAME = "on-premises directory synchronization service account"


def _sign_in_available(users: list[dict[str, Any]]) -> bool:
    """Whether the tenant's snapshot carries sign-in activity at all (needs AuditLog.Read.All + P1)."""
    return any(get_field(user, "signInActivity") for user in users)


def _sync_account_signal(name: str, display_name: str | None) -> tuple[str, str] | None:
    if name.lower().startswith(_SYNC_UPN_PREFIX) or (display_name or "").lower() == _SYNC_DISPLAY_NAME:
        return (MACHINE, "directory synchronization account")
    return None


def _sign_in_signal(sign_in: dict[str, Any], available: bool) -> tuple[str, str] | None:
    interactive = get_field(sign_in, "lastSignInDateTime") or get_field(sign_in, "lastSuccessfulSignInDateTime")
    if interactive:
        return (HUMAN, "interactive sign-ins")
    if get_field(sign_in, "lastNonInteractiveSignInDateTime"):
        return (MACHINE, "non-interactive sign-ins only")
    if available:
        return (UNKNOWN, "never signed in")
    return (HUMAN, "Entra user (sign-in data unavailable)")


def _user_classification(user: dict[str, Any], sign_in_available: bool) -> tuple[str, str]:
    name = get_field(user, "userPrincipalName") or get_field(user, "displayName") or ""
    display_name = get_field(user, "displayName")
    return resolve(
        _sync_account_signal(name, display_name),
        machine_name_signal(name, display_name),
        _sign_in_signal(get_field(user, "signInActivity") or {}, sign_in_available),
        fallback="no sign-in evidence",
    )
```

(The `_sign_in_signal` always returns a signal, so the fallback only guards future refactors.) `build_inventory` computes `available = _sign_in_available(data.get("users") or [])` and `_user_record` uses `_user_classification(user, available)` for `classification`/`classification_reason`. `_sp_record` sets `classification_reason="service principal"`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `UV_FROZEN=1 uv run pytest test/identity_inventory/test_azure.py -q`
Expected: PASS — note existing tests asserting human-by-default users may now need a `signInActivity` in their fixtures or an updated expectation matching the availability rule; preserve each test's original intent.

- [ ] **Step 5: Commit (if approved)**

```bash
git add cloudsplaining/identity_inventory/azure.py test/identity_inventory/test_azure.py
git commit -m "feat: identity_inventory(azure): sign-in-shape classification with availability-gated soft default"
```

---

### Task 7: OCI — SCIM capabilities, activity signal, honest unknown

**Files:**
- Modify: `cloudsplaining/identity_inventory/oci.py`
- Test: `test/identity_inventory/test_oci.py`

**Interfaces:**
- Consumes: `resolve`, `machine_name_signal` (Task 2); `UNKNOWN` (Task 1).
- Produces (oci.py internals): `USER_CAPABILITIES_EXTENSION = "urn:ietf:params:scim:schemas:oracle:idcs:extension:capabilities:User"`; `_capabilities(user) -> dict` (classic key wins over SCIM extension); `_user_classification(user, name, last_login) -> tuple[str, str]`. Reasons: `"MFA enrolled"`, `"console login recorded"`, `"API-key-only capabilities"`, `"console-capable (default)"`, `"no capability or activity evidence"`, `"workload identity"` (dynamic groups).

- [ ] **Step 1: Write the failing test**

Append to `test/identity_inventory/test_oci.py`:

```python
class TestOciClassificationSignals(unittest.TestCase):
    def _record(self, user):
        return next(r for r in build_inventory({"users": [user]}) if r.identity_type == "user")

    def test_scim_capabilities_api_keys_only_is_machine(self):
        record = self._record(
            {
                "id": "ocid1.user.oc1..a",
                "userName": "quiet-account",
                "urn:ietf:params:scim:schemas:oracle:idcs:extension:capabilities:User": {
                    "canUseConsolePassword": False,
                    "canUseApiKeys": True,
                },
            }
        )
        self.assertEqual(record.classification, "machine")
        self.assertEqual(record.classification_reason, "API-key-only capabilities")

    def test_console_capable_is_soft_human(self):
        record = self._record(
            {
                "id": "ocid1.user.oc1..b",
                "userName": "quiet-account",
                "capabilities": {"canUseConsolePassword": True, "canUseApiKeys": True},
            }
        )
        self.assertEqual(record.classification, "human")
        self.assertEqual(record.classification_reason, "console-capable (default)")

    def test_mfa_beats_capabilities(self):
        record = self._record(
            {
                "id": "ocid1.user.oc1..c",
                "userName": "quiet-account",
                "isMfaActivated": True,
                "capabilities": {"canUseConsolePassword": False, "canUseApiKeys": True},
            }
        )
        self.assertEqual(record.classification, "human")
        self.assertEqual(record.classification_reason, "MFA enrolled")

    def test_login_activity_is_human(self):
        record = self._record(
            {
                "id": "ocid1.user.oc1..d",
                "userName": "quiet-account",
                "lastSuccessfulLoginTime": "2026-07-01T00:00:00Z",
            }
        )
        self.assertEqual(record.classification, "human")
        self.assertEqual(record.classification_reason, "console login recorded")

    def test_no_evidence_is_unknown(self):
        record = self._record({"id": "ocid1.user.oc1..e", "userName": "quiet-account"})
        self.assertEqual(record.classification, "unknown")
        self.assertEqual(record.classification_reason, "no capability or activity evidence")

    def test_dynamic_group_reason(self):
        records = build_inventory({"dynamicGroups": [{"id": "ocid1.dg.oc1..x", "name": "workers"}]})
        self.assertEqual(records[0].classification_reason, "workload identity")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `UV_FROZEN=1 uv run pytest test/identity_inventory/test_oci.py -q`
Expected: FAIL — SCIM-capability user classifies human today; reasons are None.

- [ ] **Step 3: Write minimal implementation**

In `cloudsplaining/identity_inventory/oci.py`:

```python
USER_CAPABILITIES_EXTENSION = "urn:ietf:params:scim:schemas:oracle:idcs:extension:capabilities:User"


def _capabilities(user: dict[str, Any]) -> dict[str, Any]:
    """Capability flags from the classic key merged over the Identity Domains SCIM extension."""
    return {**(user.get(USER_CAPABILITIES_EXTENSION) or {}), **(user.get("capabilities") or {})}


def _capability_signal(capabilities: dict[str, Any]) -> tuple[str, str] | None:
    console = get_field(capabilities, "canUseConsolePassword")
    api_keys = get_field(capabilities, "canUseApiKeys")
    if console is False and as_bool(api_keys):
        return (MACHINE, "API-key-only capabilities")
    if as_bool(console):
        return (HUMAN, "console-capable (default)")
    return None


def _user_classification(user: dict[str, Any], name: str, last_login: object) -> tuple[str, str]:
    activity: tuple[str, str] | None = None
    if as_bool(get_field(user, "isMfaActivated")):
        activity = (HUMAN, "MFA enrolled")
    elif parse_timestamp(last_login) is not None:
        activity = (HUMAN, "console login recorded")
    return resolve(
        machine_name_signal(name),
        activity,
        _capability_signal(_capabilities(user)),
        fallback="no capability or activity evidence",
    )
```

`_user_record` extracts `last_login` (the same expression currently feeding `last_used`) once, passes it to both, and sets `classification`/`classification_reason`. Delete `_is_machine_user`. `_dynamic_group_record` gets `classification_reason="workload identity"`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `UV_FROZEN=1 uv run pytest test/identity_inventory/test_oci.py -q`
Expected: PASS — existing tests asserting the old human default for capability-less users need updating to `unknown` (that flip is the point; keep each test's scenario, update its expectation and name).

- [ ] **Step 5: Commit (if approved)**

```bash
git add cloudsplaining/identity_inventory/oci.py test/identity_inventory/test_oci.py
git commit -m "feat: identity_inventory(oci): SCIM capabilities, activity signals, honest unknown"
```

---

### Task 8: GCP — reasons + gserviceaccount-as-user rule

**Files:**
- Modify: `cloudsplaining/identity_inventory/gcp.py`
- Test: `test/identity_inventory/test_gcp.py`

**Interfaces:**
- Consumes: `machine_name_signal` (Task 2 — its domain rule does the gserviceaccount work).
- Produces: reasons `"service account"`, `"Workspace directory user"`, `"user: IAM binding member"`, plus machine-name/domain reasons from Task 2. No `unknown` paths (member types are structural).

- [ ] **Step 1: Write the failing test**

Append to `test/identity_inventory/test_gcp.py` (reuse its `_snapshot()` / `_by_name` helpers):

```python
class TestGcpClassificationReasons(unittest.TestCase):
    def test_user_binding_member_with_gserviceaccount_domain_is_machine(self):
        data = _snapshot()
        data["bindings"] = [
            {"role": "roles/viewer", "members": ["user:sa-misfiled@proj.iam.gserviceaccount.com"]}
        ]
        record = _by_name(build_inventory(data), "sa-misfiled@proj.iam.gserviceaccount.com")
        self.assertEqual(record.classification, "machine")
        self.assertEqual(record.classification_reason, "workload email domain (gserviceaccount.com)")

    def test_reasons_present_on_all_gcp_records(self):
        records = build_inventory(_snapshot())
        self.assertTrue(all(r.classification_reason for r in records))
        by_type = {r.identity_type: r.classification_reason for r in records}
        self.assertEqual(by_type.get("service_account"), "service account")

    def test_workspace_user_reason(self):
        record = _by_name(build_inventory(_snapshot()), "dev@corp.com")  # a _snapshot() directory user
        self.assertEqual(record.classification, "human")
        self.assertEqual(record.classification_reason, "Workspace directory user")
```

(Adjust `dev@corp.com` to a directory user actually present in `_snapshot()`; a binding-only member asserts `"user: IAM binding member"` analogously.)

- [ ] **Step 2: Run test to verify it fails**

Run: `UV_FROZEN=1 uv run pytest test/identity_inventory/test_gcp.py -q`
Expected: FAIL — gserviceaccount `user:` member classifies human; reasons are None.

- [ ] **Step 3: Write minimal implementation**

In `cloudsplaining/identity_inventory/gcp.py` (this file just changed for audit-log lifecycle — build on the current working-tree version):

```python
from cloudsplaining.identity_inventory.classify import machine_name_signal
```

In `_sa_record`: `classification_reason="service account"`. In `_user_record`:

```python
    classification, reason = machine_name_signal(email) or (HUMAN, "Workspace directory user")
```

In `_member_user_record`:

```python
    classification, reason = machine_name_signal(email) or (HUMAN, "user: IAM binding member")
```

(Both then pass `classification=classification, classification_reason=reason`. The `is_machine_name` import can be dropped once nothing uses it.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `UV_FROZEN=1 uv run pytest test/identity_inventory/test_gcp.py -q`
Expected: PASS, including the 2026-08-02 audit-lifecycle tests already in the file.

- [ ] **Step 5: Commit (if approved)**

```bash
git add cloudsplaining/identity_inventory/gcp.py test/identity_inventory/test_gcp.py
git commit -m "feat: identity_inventory(gcp): classification reasons and gserviceaccount user-member rule"
```

---

### Task 9: integration — scan path, CLI, full suite

**Files:**
- Modify: `test/identity_inventory/test_scan_integration.py`
- Modify (as needed): `test/identity_inventory/test_inventory.py`, `test/identity_inventory/test_cli.py`
- Test: the whole `test/` tree.

**Interfaces:**
- Consumes: everything above.
- Produces: green suite; written `iam-results-*.json` records carry `classification_reason`; scan accepts snapshots containing the new keys.

- [ ] **Step 1: Extend the integration test (failing first if Task 5's schema step was skipped)**

In `test/identity_inventory/test_scan_integration.py`, extend the snapshot dict with the Task 5 keys and assert on the written output:

```python
        # inside the existing test that writes iam-results-acct.json
        records = written["identity_inventory"]
        self.assertTrue(all("classification_reason" in record for record in records))
        self.assertTrue(
            all(record["classification"] in ("human", "machine", "unknown") for record in records)
        )
```

- [ ] **Step 2: Run the full suite**

Run: `UV_FROZEN=1 uv run pytest test/ -q`
Expected: failures only in tests still asserting pre-`unknown` defaults (e.g. `test_inventory.py`, `test_cli.py` exact-dict assertions).

- [ ] **Step 3: Fix remaining assertions**

Update expectations to the new contract — membership assertions preferred; where a test asserted a silent-guess `human`, decide from the fixture what the *evidence* supports and assert that (with its reason string verbatim from this plan's vocabulary).

- [ ] **Step 4: Run the full suite again**

Run: `UV_FROZEN=1 uv run pytest test/ -q`
Expected: PASS.

- [ ] **Step 5: Commit (if approved)**

```bash
git add test/
git commit -m "test: identity classification contract — reasons everywhere, unknown accepted end to end"
```

---

### Task 10: docs — precedence, reason vocabulary, permissions

**Files:**
- Modify: `docs/identity-inventory-design.md`
- Modify: `docs/identity-inventory-permissions.md`

- [ ] **Step 1: Update `docs/identity-inventory-design.md`**

Replace the classification paragraphs with: the four-layer precedence (hard structure → machine-name → credential/activity shape → unknown), the `classification_reason` field, and a table of the exact reason strings from this plan (copy them verbatim; group by human/machine/unknown). Note the two deliberate soft defaults (`"Entra user (sign-in data unavailable)"`, `"console-capable (default)"`) and the AWS fallback distinction (`report unavailable` vs `created after report generated`).

- [ ] **Step 2: Update `docs/identity-inventory-permissions.md`**

AWS table: add a row — `iam:ListAccessKeys` + `iam:GetLoginProfile` + `iam:ListMFADevices` (all inside `SecurityAudit` / `ReadOnlyAccess`) → live classification of users missing from the cached credential report; without them such users are `unknown` (or classified from CloudTrail credential events). CloudTrail row: note the two extra event names. Azure section: note that without `AuditLog.Read.All`/P1 sign-in data, users soft-default to human with an explicit reason.

- [ ] **Step 3: Commit (if approved)**

```bash
git add docs/identity-inventory-design.md docs/identity-inventory-permissions.md
git commit -m "docs: identity classification precedence, reason vocabulary, permissions"
```

---

### Task 11: fixtures + gates

**Files:**
- Regenerated: `examples/files/example-iam-data.json`, `cloudsplaining/output/dist/sampleData.js` (via `just generate-report`)

- [ ] **Step 1: Regenerate example fixtures**

Run: `UV_FROZEN=1 uv run just generate-report`
Expected: example identity-inventory records now carry `classification_reason`; neutral-named example users without credential-report data flip to `unknown` with `"no credential evidence: credential report unavailable"` — that is correct per the spec, not a regression.

- [ ] **Step 2: Sync + JS gates**

Run: `UV_FROZEN=1 uv run just check-sampledata-sync && UV_FROZEN=1 uv run just test-js`
Expected: PASS (the report UI does not read `classification`, so mocha only cares via the sync check).

- [ ] **Step 3: Type check + lint**

Run: `UV_FROZEN=1 uv run just type-check && UV_FROZEN=1 uv run just lint`
Expected: type-check PASS; lint may show the ~47 pre-existing `cloudsplaining/multicloud/` ruff errors (baseline) — zero *new* errors in files this plan touched.

- [ ] **Step 4: Full pre-push gate (minus commit/push)**

Run: `UV_FROZEN=1 uv run just unit-tests && UV_FROZEN=1 uv run just safety-scan`
Expected: PASS; safety-scan must find no AWS keys/account IDs in staged or tracked files (the spec/plan docs use only the documentation account `111122223333`).

- [ ] **Step 5: Report regression check (recommended)**

Run the `report-regression-check` skill (snapshots, regenerates, diffs findings): findings must be unchanged — this feature touches inventory, not findings.

- [ ] **Step 6: Commit fixtures (if approved)**

```bash
git add examples/files/example-iam-data.json cloudsplaining/output/dist/sampleData.js
git commit -m "chore: regenerate example fixtures with classification reasons"
```
