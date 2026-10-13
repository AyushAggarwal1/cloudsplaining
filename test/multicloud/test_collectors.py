import unittest
from datetime import datetime, timedelta, timezone

from cloudsplaining.identity_inventory.azure import build_inventory as build_azure_inventory
from cloudsplaining.multicloud.collectors import get_collector
from cloudsplaining.multicloud.collectors.azure import AzureCollector
from cloudsplaining.multicloud.collectors.base import Collector, CollectorDependencyError


# Anchored to the wall clock because the collector's audit-window logic clamps
# to the service's rolling 365-day retention bound; fixed dates would rot.
_OCI_NOW = datetime.now(timezone.utc)
_OCI_USER_CREATED = _OCI_NOW - timedelta(days=180)
_OCI_DG_CREATED = _OCI_NOW - timedelta(days=120)
_OCI_LAST_LOGIN = _OCI_NOW - timedelta(days=30)


class _FakeIdentityClient:
    """Minimal stand-in for oci.identity.IdentityClient."""

    class _Resp:
        def __init__(self, data):
            self.data = data
            self.next_page = None

    def __init__(self):
        capabilities = type("C", (), {"can_use_console_password": False, "can_use_api_keys": True})()
        self._user = type(
            "U",
            (),
            {
                "id": "ocid.user.alice",
                "name": "alice",
                "description": None,
                "email": "alice@corp.com",
                "time_created": _OCI_USER_CREATED,
                "last_successful_login_time": _OCI_LAST_LOGIN,
                "is_mfa_activated": False,
                "capabilities": capabilities,
            },
        )()
        self._dynamic_group = type(
            "D",
            (),
            {
                "id": "ocid.dynamicgroup.dg",
                "name": "instances-dg",
                "matching_rule": "instance.compartment.id = 'x'",
                "time_created": _OCI_DG_CREATED,
            },
        )()
        self._group = type("G", (), {"id": "ocid.group.admins", "name": "Administrators", "description": None})()
        self._policy = type(
            "P",
            (),
            {
                "id": "ocid.policy.p1",
                "name": "p1",
                "compartment_id": "ocid.tenancy",
                "statements": ["Allow group Administrators to manage all-resources in tenancy"],
            },
        )()
        self._membership = type("M", (), {"user_id": "ocid.user.alice"})()

    def list_users(self, compartment_id, page=None):
        return self._Resp([self._user])

    def list_groups(self, compartment_id, page=None):
        return self._Resp([self._group])

    def list_dynamic_groups(self, compartment_id, page=None):
        return self._Resp([self._dynamic_group])

    def list_compartments(self, compartment_id, page=None):
        return self._Resp([])

    def list_policies(self, compartment_id, page=None):
        return self._Resp([self._policy] if compartment_id == "ocid.tenancy" else [])

    def list_user_group_memberships(self, compartment_id, group_id, page=None):
        return self._Resp([self._membership])

    def list_domains(self, compartment_id, page=None):
        return self._Resp(getattr(self, "domains", []))


def _audit_event(event_type, resource_name, principal_name):
    identity = type("I", (), {"principal_name": principal_name})()
    data = type("D", (), {"resource_name": resource_name, "identity": identity})()
    event_time = {
        "alice": _OCI_USER_CREATED,
        "instances-dg": _OCI_DG_CREATED,
    }.get(resource_name, _OCI_NOW)
    return type(
        "E",
        (),
        {
            "event_type": event_type,
            "event_time": event_time,
            "data": data,
        },
    )()


class _FakeAuditClient:
    """Minimal stand-in for oci.audit.AuditClient."""

    class _Resp:
        def __init__(self, data, next_page=None):
            self.data = data
            self.next_page = next_page

    def __init__(self, error=None):
        self.error = error
        self.windows = []
        #: (compartment_id, start_time, end_time) per call: which compartment each window was queried in.
        self.calls = []

    def list_events(self, compartment_id, start_time, end_time, page=None):
        if self.error is not None:
            raise self.error
        # The real service validates the window on every call, including
        # paginated ones issued after time has passed.
        if start_time < datetime.now(timezone.utc) - timedelta(days=365):
            raise RuntimeError("startTime can not be older than 365 days")
        self.windows.append((start_time, end_time))
        self.calls.append((compartment_id, start_time, end_time))
        return self._Resp(
            [
                _audit_event("com.oraclecloud.identityControlPlane.CreateUser", "alice", "admin@corp.com"),
                _audit_event("com.oraclecloud.computeApi.LaunchInstance", "web-vm", "admin@corp.com"),
                _audit_event(
                    "com.oraclecloud.identityControlPlane.CreateDynamicGroup", "instances-dg", "admin@corp.com"
                ),
            ]
        )


class _FakePagingAuditClient(_FakeAuditClient):
    """Serves one creation event per page; every window pages endlessly (up to total_pages)."""

    def __init__(self, total_pages):
        super().__init__()
        self.total_pages = total_pages
        self.pages_served = 0

    def list_events(self, compartment_id, start_time, end_time, page=None):
        self.windows.append((start_time, end_time))
        self.pages_served += 1
        events = [_audit_event("com.oraclecloud.identityControlPlane.CreateUser", "alice", "admin@corp.com")]
        next_page = str(self.pages_served) if self.pages_served < self.total_pages else None
        return self._Resp(events, next_page=next_page)


class TestCollectors(unittest.TestCase):
    def test_get_collector_aliases(self):
        self.assertEqual(get_collector("oci", tenancy_id="t", client=_FakeIdentityClient()).name, "oci")
        self.assertEqual(get_collector("oracle", tenancy_id="t", client=_FakeIdentityClient()).name, "oci")

    def test_unknown_provider(self):
        with self.assertRaises(ValueError):
            get_collector("ibm")

    def test_missing_subscription_id_raises(self):
        with self.assertRaises(ValueError):
            get_collector("azure")

    def test_dependency_error_is_actionable(self):
        # Use a guaranteed-missing module so the test does not depend on whether
        # the real cloud SDK happens to be installed in the environment.
        collector = get_collector("gcp", project_id="demo")
        with self.assertRaises(CollectorDependencyError) as ctx:
            collector._import("cloudsplaining_missing_sdk_xyz")
        self.assertIn("cloudsplaining[gcp]", str(ctx.exception))

    def test_oci_snapshot_records_tenancy_as_account_id(self):
        collector = get_collector("oci", tenancy_id="ocid.tenancy", client=_FakeIdentityClient())
        snapshot = collector.collect()
        self.assertEqual(snapshot["account_id"], "ocid.tenancy")
        self.assertEqual(next(iter(snapshot)), "account_id")

    def test_oci_collector_with_injected_client(self):
        collector = get_collector("oci", tenancy_id="ocid.tenancy", client=_FakeIdentityClient())
        snapshot = collector.collect()
        self.assertEqual([u["name"] for u in snapshot["users"]], ["alice"])
        self.assertEqual(snapshot["groupMemberships"], {"Administrators": ["alice"]})
        self.assertEqual(len(snapshot["policies"]), 1)

    def test_oci_collector_emits_identity_lifecycle_fields(self):
        collector = get_collector("oci", tenancy_id="ocid.tenancy", client=_FakeIdentityClient())
        snapshot = collector.collect()
        user = snapshot["users"][0]
        self.assertEqual(user["timeCreated"], _OCI_USER_CREATED)
        self.assertEqual(user["lastSuccessfulLoginTime"], _OCI_LAST_LOGIN)
        self.assertIs(user["isMfaActivated"], False)
        self.assertEqual(user["email"], "alice@corp.com")
        self.assertEqual(user["capabilities"], {"canUseConsolePassword": False, "canUseApiKeys": True})
        dynamic_group = snapshot["dynamicGroups"][0]
        self.assertEqual(dynamic_group["timeCreated"], _OCI_DG_CREATED)

    def test_oci_snapshot_feeds_identity_inventory(self):
        from cloudsplaining.identity_inventory.oci import build_inventory

        collector = get_collector("oci", tenancy_id="ocid.tenancy", client=_FakeIdentityClient())
        records = {r.name: r for r in build_inventory(collector.collect())}
        # alice: API keys, no console password, no MFA -> machine service account.
        self.assertEqual(records["alice"].classification, "machine")
        self.assertEqual(records["alice"].created_at, _OCI_USER_CREATED)
        self.assertEqual(records["instances-dg"].classification, "machine")

    def test_oci_snapshot_round_trips_through_engine(self):
        from cloudsplaining.multicloud.oci.engine import OciProvider
        from cloudsplaining.multicloud.report_aws import render

        collector = get_collector("oci", tenancy_id="ocid.tenancy", client=_FakeIdentityClient())
        report = render(OciProvider().scan(collector.collect()))
        self.assertEqual(len(report["users"]), 1)
        self.assertTrue(report["customer_managed_policies"])

    def test_base_is_abstract(self):
        self.assertTrue(issubclass(Collector, object))
        with self.assertRaises(TypeError):
            Collector()  # abstract


class _FakeIdentityDomainsClient:
    """Minimal stand-in for oci.identity_domains.IdentityDomainsClient."""

    class _Resp:
        def __init__(self, data):
            self.data = data

    def __init__(self, error=None):
        self.error = error
        self.calls = []

    def list_users(self, attributes=None, count=None, start_index=None):
        if self.error is not None:
            raise self.error
        self.calls.append((attributes, count, start_index))
        created_by = type("CB", (), {"display": "domain-admin@corp.com", "value": "ocid.user.domain-admin"})()
        user = type("DU", (), {"ocid": "ocid.user.alice", "user_name": "alice", "idcs_created_by": created_by})()
        return self._Resp(type("Users", (), {"resources": [user] if start_index == 1 else []})())


_DEFAULT_DOMAIN_URL = "https://default.identity.example"


def _default_domain_identity_client():
    identity = _FakeIdentityClient()
    identity.domains = [_domain("Default", "DEFAULT", "ocid.tenancy", _DEFAULT_DOMAIN_URL)]
    return identity


class TestOciIdentityDomains(unittest.TestCase):
    def _collector(self, domains_client):
        return get_collector(
            "oci",
            tenancy_id="ocid.tenancy",
            client=_default_domain_identity_client(),
            identity_domains_clients={_DEFAULT_DOMAIN_URL: domains_client},
        )

    def test_identity_domains_created_by_merged_into_users(self):
        snapshot = self._collector(_FakeIdentityDomainsClient()).collect()
        self.assertEqual(
            snapshot["users"][0]["idcsCreatedBy"],
            {"display": "domain-admin@corp.com", "value": "ocid.user.domain-admin"},
        )

    def test_identity_domains_attribution_outlives_audit_retention(self):
        from cloudsplaining.identity_inventory.oci import build_inventory

        # idcsCreatedBy is stored on the user, so it attributes identities whose
        # creation events left the 365-day audit window long ago.
        identity = _default_domain_identity_client()
        identity._user.time_created = _OCI_NOW - timedelta(days=900)
        collector = get_collector(
            "oci",
            tenancy_id="ocid.tenancy",
            client=identity,
            identity_domains_clients={_DEFAULT_DOMAIN_URL: _FakeIdentityDomainsClient()},
        )
        records = {record.name: record for record in build_inventory(collector.collect())}
        self.assertEqual(records["alice"].created_by, "domain-admin@corp.com")

    def test_identity_domains_enrichment_fails_open(self):
        snapshot = self._collector(_FakeIdentityDomainsClient(error=RuntimeError("NotAuthorizedOrNotFound"))).collect()
        self.assertEqual([u["name"] for u in snapshot["users"]], ["alice"])
        self.assertNotIn("idcsCreatedBy", snapshot["users"][0])


class TestOciAuditCollection(unittest.TestCase):
    def _collector(self, audit_client):
        return get_collector("oci", tenancy_id="ocid.tenancy", client=_FakeIdentityClient(), audit_client=audit_client)

    def test_collect_includes_creation_audit_events(self):
        audit = _FakeAuditClient()
        snapshot = self._collector(audit).collect()
        self.assertIn(
            {
                "eventType": "com.oraclecloud.identityControlPlane.CreateUser",
                "eventTime": _OCI_USER_CREATED,
                "data": {"resourceName": "alice", "identity": {"principalName": "admin@corp.com"}},
            },
            snapshot["auditEvents"],
        )
        # Non-creation events are dropped so snapshots stay small.
        kinds = [event["eventType"] for event in snapshot["auditEvents"]]
        self.assertNotIn("com.oraclecloud.computeApi.LaunchInstance", kinds)

    def test_audit_queries_target_identity_creation_times(self):
        # Creation events are emitted at ~timeCreated, so the collector queries
        # a short window around each identity's creation instead of scanning
        # the whole retention window, which takes minutes on active tenancies.
        audit = _FakeAuditClient()
        self._collector(audit).collect()
        self.assertEqual(len(audit.windows), 2)
        # Newest identity first: under page-budget pressure the most recent
        # (most attributable) identities win.
        for (start_time, end_time), created in zip(audit.windows, [_OCI_DG_CREATED, _OCI_USER_CREATED]):
            self.assertLessEqual(start_time, created)
            self.assertGreaterEqual(end_time, created)
            self.assertLessEqual(end_time - start_time, timedelta(minutes=5))

    def test_identities_outside_retention_are_not_queried(self):
        # Their creation events are beyond the audit service's 365-day
        # retention, so a query could only fail validation or return nothing.
        identity = _FakeIdentityClient()
        identity._user.time_created = _OCI_NOW - timedelta(days=400)
        identity._dynamic_group.time_created = _OCI_NOW - timedelta(days=400)
        audit = _FakeAuditClient()
        collector = get_collector("oci", tenancy_id="ocid.tenancy", client=identity, audit_client=audit)
        with self.assertNoLogs("cloudsplaining.multicloud.collectors.oci", level="WARNING"):
            snapshot = collector.collect()
        self.assertEqual(audit.windows, [])
        self.assertEqual(snapshot["auditEvents"], [])

    def test_audit_events_fail_open(self):
        snapshot = self._collector(_FakeAuditClient(error=RuntimeError("NotAuthorizedOrNotFound"))).collect()
        self.assertEqual(snapshot["auditEvents"], [])
        self.assertEqual([u["name"] for u in snapshot["users"]], ["alice"])

    def test_audit_events_skipped_without_audit_client(self):
        # Injected-identity-client mode must not build a real AuditClient.
        collector = get_collector("oci", tenancy_id="ocid.tenancy", client=_FakeIdentityClient())
        self.assertEqual(collector.collect()["auditEvents"], [])

    def test_audit_scan_is_page_capped_per_window(self):
        # A noisy window (e.g. scanner traffic around a creation time) must
        # not starve the others: each window gets a bounded number of pages
        # and every window is still visited.
        audit = _FakePagingAuditClient(total_pages=300)
        snapshot = self._collector(audit).collect()
        self.assertEqual(len(set(audit.windows)), 2)
        self.assertLessEqual(audit.pages_served, 10)
        self.assertTrue(snapshot["auditEvents"])

    def test_snapshot_with_audit_events_feeds_created_by(self):
        from cloudsplaining.identity_inventory.oci import build_inventory

        snapshot = self._collector(_FakeAuditClient()).collect()
        records = {record.name: record for record in build_inventory(snapshot)}
        self.assertEqual(records["alice"].created_by, "admin@corp.com")
        self.assertEqual(records["instances-dg"].created_by, "admin@corp.com")


class _StubGraphAzureCollector(AzureCollector):
    """Serves canned Graph pages; optionally rejects signInActivity like a tenant without AuditLog.Read.All."""

    def __init__(self, deny_sign_in_activity, deny_audit_logs: bool = False):
        credential = type("Cred", (), {"get_token": lambda self, scope: type("T", (), {"token": "t"})()})()
        super().__init__(subscription_id="sub", credential=credential)
        self.deny_sign_in_activity = deny_sign_in_activity
        self.deny_audit_logs = deny_audit_logs
        self.paths = []

    def _graph_list(self, token, path):
        self.paths.append(path)
        if self.deny_sign_in_activity and "signInActivity" in path:
            raise RuntimeError("Authentication_RequestFromNonPremiumTenantOrB2CTenant")
        if "directoryAudits" in path or "servicePrincipalSignInActivities" in path:
            if self.deny_audit_logs:
                raise RuntimeError("Authorization_RequestDenied")
            if "directoryAudits" in path:
                return [
                    {
                        "activityDisplayName": "Add user",
                        "initiatedBy": {"user": {"userPrincipalName": "admin@contoso.com"}},
                        "targetResources": [{"id": "u1", "userPrincipalName": "jane@contoso.com"}],
                    }
                ]
            return [{"appId": "a1", "lastSignInActivity": {"lastSignInDateTime": "2026-07-01T12:00:00Z"}}]
        if path.startswith("/users"):
            return [{"id": "u1", "userPrincipalName": "jane@contoso.com"}]
        if path.startswith("/servicePrincipals"):
            return [{"id": "sp1", "appId": "a1", "displayName": "deploy-pipeline"}]
        if path.startswith("/groups/"):
            return []
        return [{"id": "g1", "displayName": "Engineering"}]


class _FakeGcpRequest:
    def __init__(self, data):
        self._data = data

    def execute(self):
        if isinstance(self._data, Exception):
            raise self._data
        return self._data


class _FakeGcpIam:
    """Chameleon stand-in for the IAM discovery client's fluent chains."""

    def projects(self):
        return self

    def serviceAccounts(self):
        return self

    def roles(self):
        return self

    def list(self, **kwargs):
        if "name" in kwargs:
            data = {"accounts": [{"email": "sa@demo.iam.gserviceaccount.com", "uniqueId": "111", "displayName": "sa"}]}
        else:
            data = {"roles": []}
        return _FakeGcpRequest(data)

    def list_next(self, request, response):
        return None

    def get(self, name):
        return _FakeGcpRequest({"name": name, "title": name, "includedPermissions": ["iam.roles.get"]})


class _FakeGcpCrm:
    def projects(self):
        return self

    def getIamPolicy(self, resource, body):
        bindings = [
            {"role": "roles/owner", "members": ["user:jane@corp.com", "serviceAccount:sa@demo.iam.gserviceaccount.com"]}
        ]
        return _FakeGcpRequest({"bindings": bindings})


class _FakeGcpPolicyAnalyzer:
    def __init__(self, error=None):
        self.error = error
        self.parents = []

    def projects(self):
        return self

    def locations(self):
        return self

    def activityTypes(self):
        return self

    def activities(self):
        return self

    def query(self, parent, pageSize):
        self.parents.append(parent)
        if self.error:
            return _FakeGcpRequest(self.error)
        activity = {
            "activityType": "serviceAccountLastAuthentication",
            "fullResourceName": "//iam.googleapis.com/projects/demo/serviceAccounts/sa@demo.iam.gserviceaccount.com",
            "activity": {
                "lastAuthenticatedTime": "2026-07-27T07:00:00Z",
                "serviceAccount": {"email": "sa@demo.iam.gserviceaccount.com"},
            },
        }
        return _FakeGcpRequest({"activities": [activity]})

    def query_next(self, request, response):
        return None


class _FakeGcpLogging:
    def __init__(self, error=None):
        self.error = error
        self.bodies = []

    def entries(self):
        return self

    def list(self, body):
        self.bodies.append(body)
        if self.error:
            return _FakeGcpRequest(self.error)
        if "SetIamPolicy" in body.get("filter", ""):
            entry = {
                "timestamp": "2026-01-05T00:00:00Z",
                "protoPayload": {
                    "methodName": "SetIamPolicy",
                    "authenticationInfo": {"principalEmail": "admin@corp.com"},
                    "serviceData": {
                        "policyDelta": {"bindingDeltas": [{"action": "ADD", "member": "user:jane@corp.com"}]}
                    },
                },
            }
        else:
            entry = {
                "timestamp": "2026-07-20T00:00:00Z",
                "protoPayload": {
                    "methodName": "storage.buckets.list",
                    "authenticationInfo": {"principalEmail": "jane@corp.com"},
                },
            }
        return _FakeGcpRequest({"entries": [entry]})

    def list_next(self, request, response):
        return None


class _FakePagingGcpLogging:
    """Serves one entry per page, up to total_pages pages per distinct filter."""

    def __init__(self, total_pages):
        self.total_pages = total_pages
        self._pages_served = {}

    def entries(self):
        return self

    def _entry(self, body):
        if "SetIamPolicy" in body.get("filter", ""):
            return {"timestamp": "2026-01-05T00:00:00Z", "protoPayload": {"methodName": "SetIamPolicy"}}
        return {"timestamp": "2026-07-20T00:00:00Z", "protoPayload": {"methodName": "storage.buckets.list"}}

    def list(self, body):
        request = _FakeGcpRequest({"entries": [self._entry(body)]})
        request.body = body
        return request

    def list_next(self, request, response):
        key = request.body.get("filter", "")
        served = self._pages_served.get(key, 1)
        if served >= self.total_pages:
            return None
        self._pages_served[key] = served + 1
        return self.list(request.body)


class _BusyProjectGcpLogging:
    """Emulates a busy project's Admin Activity log with real filter/order semantics.

    A wall of SetIamPolicy grants (oldest-first: old@corp.com added early,
    recent@corp.com added last) buries one CreateServiceAccount event in the
    middle of the retention window. One entry per page so page caps bite.
    """

    def __init__(self, grant_count=100):
        def grant(index, member):
            return {
                "timestamp": f"2025-{1 + index // 28:02d}-{1 + index % 28:02d}T00:00:00Z",
                "protoPayload": {
                    "methodName": "SetIamPolicy",
                    "authenticationInfo": {"principalEmail": "admin@corp.com"},
                    "serviceData": {"policyDelta": {"bindingDeltas": [{"action": "ADD", "member": member}]}},
                },
            }

        self._entries = [grant(i, "user:old@corp.com" if i < 3 else "user:noise@corp.com") for i in range(grant_count)]
        self._entries[grant_count // 2] = {
            "timestamp": self._entries[grant_count // 2]["timestamp"],
            "protoPayload": {
                "methodName": "google.iam.admin.v1.CreateServiceAccount",
                "authenticationInfo": {"principalEmail": "creator@corp.com"},
                "response": {"email": "buried-sa@demo.iam.gserviceaccount.com"},
            },
        }
        # Recent but not among the newest few entries, so the capped newest-first
        # *activity* pass cannot rescue it by accident.
        self._entries[grant_count - 6] = grant(grant_count - 6, "user:recent@corp.com")

    def entries(self):
        return self

    def _matching(self, body):
        methods = [m for m in ("SetIamPolicy", "CreateServiceAccount") if f'methodName:"{m}"' in body.get("filter", "")]
        selected = [
            e for e in self._entries if not methods or any(m in e["protoPayload"]["methodName"] for m in methods)
        ]
        return sorted(selected, key=lambda e: e["timestamp"], reverse=body.get("orderBy") == "timestamp desc")

    def list(self, body):
        request = _FakeGcpRequest({"entries": self._matching(body)[:1]})
        request.body, request.cursor = body, 1
        return request

    def list_next(self, request, response):
        matching = self._matching(request.body)
        if request.cursor >= len(matching):
            return None
        nxt = _FakeGcpRequest({"entries": matching[request.cursor : request.cursor + 1]})
        nxt.body, nxt.cursor = request.body, request.cursor + 1
        return nxt


class _StubGcpCollector:
    """GcpCollector wired to fakes; import deferred so the module stays optional."""

    def __new__(cls, deny_lifecycle: bool = False):
        from cloudsplaining.multicloud.collectors.gcp import GcpCollector

        collector = GcpCollector(project_id="demo")
        error = RuntimeError("Permission denied") if deny_lifecycle else None
        collector._iam = _FakeGcpIam()
        collector._crm = _FakeGcpCrm()
        collector._policy_analyzer = _FakeGcpPolicyAnalyzer(error=error)
        collector._logging = _FakeGcpLogging(error=error)
        return collector


class TestGcpLifecycleCollection(unittest.TestCase):
    def test_gcp_snapshot_records_project_as_account_id(self):
        snapshot = _StubGcpCollector().collect()
        self.assertEqual(snapshot["account_id"], "demo")
        self.assertEqual(next(iter(snapshot)), "account_id")

    def test_collect_includes_service_account_activities(self):
        snapshot = _StubGcpCollector().collect()
        emails = [a["activity"]["serviceAccount"]["email"] for a in snapshot["serviceAccountActivities"]]
        self.assertIn("sa@demo.iam.gserviceaccount.com", emails)

    def test_collect_includes_audit_log_entries(self):
        snapshot = _StubGcpCollector().collect()
        methods = [e["protoPayload"]["methodName"] for e in snapshot["auditLogEntries"]]
        self.assertIn("SetIamPolicy", methods)
        self.assertIn("storage.buckets.list", methods)

    def test_lifecycle_endpoints_fail_open(self):
        snapshot = _StubGcpCollector(deny_lifecycle=True).collect()
        self.assertEqual(snapshot["serviceAccountActivities"], [])
        self.assertEqual(snapshot["auditLogEntries"], [])
        self.assertEqual([sa["email"] for sa in snapshot["serviceAccounts"]], ["sa@demo.iam.gserviceaccount.com"])

    def test_grant_audit_pass_is_page_capped(self):
        # A Logging API scan over the retention window can serve hundreds of
        # pages; the creation/grant pass must stop at a bounded page count.
        collector = _StubGcpCollector()
        collector._logging = _FakePagingGcpLogging(total_pages=60)
        snapshot = collector.collect()
        grants = [e for e in snapshot["auditLogEntries"] if e["protoPayload"]["methodName"] == "SetIamPolicy"]
        self.assertLessEqual(len(grants), 30)

    def test_creation_events_survive_grant_noise(self):
        # A busy project's SetIamPolicy traffic exceeds the page budget; the
        # rare CreateServiceAccount events must still be collected or every
        # service account loses created_at/created_by.
        collector = _StubGcpCollector()
        collector._logging = _BusyProjectGcpLogging()
        methods = [e["protoPayload"]["methodName"] for e in collector.collect()["auditLogEntries"]]
        self.assertTrue(any(m.endswith("CreateServiceAccount") for m in methods))

    def test_grant_page_budget_covers_both_ends_of_the_window(self):
        # The earliest retained grants date long-lived users; the newest cover
        # recently added ones. A budget spent only oldest-first goes blind to
        # everything after the horizon it starves at.
        collector = _StubGcpCollector()
        collector._logging = _BusyProjectGcpLogging()
        members = [
            str(delta.get("member"))
            for e in collector.collect()["auditLogEntries"]
            for delta in (e["protoPayload"].get("serviceData") or {}).get("policyDelta", {}).get("bindingDeltas", [])
        ]
        self.assertIn("user:old@corp.com", members)
        self.assertIn("user:recent@corp.com", members)

    def test_gcp_snapshot_feeds_identity_inventory_lifecycle(self):
        from cloudsplaining.identity_inventory.gcp import build_inventory

        snapshot = _StubGcpCollector().collect()
        records = {record.name: record for record in build_inventory(snapshot)}
        self.assertEqual(
            records["sa@demo.iam.gserviceaccount.com"].last_used,
            datetime(2026, 7, 27, 7, 0, tzinfo=timezone.utc),
        )
        jane = records["jane@corp.com"]
        self.assertEqual(jane.created_at, datetime(2026, 1, 5, tzinfo=timezone.utc))
        self.assertEqual(jane.created_by, "admin@corp.com")
        self.assertEqual(jane.last_used, datetime(2026, 7, 20, tzinfo=timezone.utc))


class _StubManagementAzureCollector(AzureCollector):
    """Azure collector with the network planes stubbed out; exercises collect()'s snapshot assembly."""

    def __init__(self):
        credential = type("Cred", (), {"get_token": lambda self, scope: type("T", (), {"token": "t"})()})()
        super().__init__(subscription_id="00000000-0000-0000-0000-00000000sub1", credential=credential)

    def _role_definitions(self):
        return []

    def _role_assignments(self):
        return []

    def _collect_graph(self, snapshot):
        return None


class TestAzureSnapshotAssembly(unittest.TestCase):
    def test_azure_snapshot_records_subscription_as_account_id(self):
        snapshot = _StubManagementAzureCollector().collect()
        self.assertEqual(snapshot["account_id"], "00000000-0000-0000-0000-00000000sub1")
        self.assertEqual(next(iter(snapshot)), "account_id")


class TestAzureGraphCollection(unittest.TestCase):
    def test_users_query_requests_lifecycle_fields(self):
        collector = _StubGraphAzureCollector(deny_sign_in_activity=False)
        snapshot = {"users": [], "groups": [], "servicePrincipals": [], "groupMemberships": {}}
        collector._collect_graph(snapshot)
        users_path = next(p for p in collector.paths if p.startswith("/users"))
        self.assertIn("createdDateTime", users_path)
        self.assertIn("signInActivity", users_path)
        sp_path = next(p for p in collector.paths if p.startswith("/servicePrincipals"))
        self.assertIn("createdDateTime", sp_path)
        self.assertEqual([u["id"] for u in snapshot["users"]], ["u1"])

    def test_users_query_falls_back_without_sign_in_activity(self):
        collector = _StubGraphAzureCollector(deny_sign_in_activity=True)
        snapshot = {"users": [], "groups": [], "servicePrincipals": [], "groupMemberships": {}}
        collector._collect_graph(snapshot)
        users_paths = [p for p in collector.paths if p.startswith("/users")]
        self.assertEqual(len(users_paths), 2)
        self.assertIn("signInActivity", users_paths[0])
        self.assertNotIn("signInActivity", users_paths[1])
        self.assertEqual([u["id"] for u in snapshot["users"]], ["u1"])

    def test_collect_graph_fetches_creation_audits_and_sp_sign_ins(self) -> None:
        collector = _StubGraphAzureCollector(deny_sign_in_activity=False)
        snapshot = {"users": [], "groups": [], "servicePrincipals": [], "groupMemberships": {}}
        collector._collect_graph(snapshot)
        audit_path = next(p for p in collector.paths if "directoryAudits" in p)
        self.assertIn("Add user", audit_path)
        self.assertIn("Add service principal", audit_path)
        self.assertIn("Invite external user", audit_path)
        sp_sign_in_path = next(p for p in collector.paths if "servicePrincipalSignInActivities" in p)
        self.assertIn("https://graph.microsoft.com/beta", sp_sign_in_path)
        self.assertEqual(snapshot["directoryAudits"][0]["activityDisplayName"], "Add user")
        self.assertEqual(snapshot["servicePrincipalSignInActivities"][0]["appId"], "a1")

    def test_audit_endpoints_fail_open(self) -> None:
        collector = _StubGraphAzureCollector(deny_sign_in_activity=False, deny_audit_logs=True)
        snapshot = {"users": [], "groups": [], "servicePrincipals": [], "groupMemberships": {}}
        collector._collect_graph(snapshot)
        self.assertEqual(snapshot["directoryAudits"], [])
        self.assertEqual(snapshot["servicePrincipalSignInActivities"], [])
        self.assertEqual([u["id"] for u in snapshot["users"]], ["u1"])

    def test_azure_snapshot_feeds_identity_inventory_lifecycle(self) -> None:
        collector = _StubGraphAzureCollector(deny_sign_in_activity=False)
        snapshot = {"users": [], "groups": [], "servicePrincipals": [], "groupMemberships": {}}
        collector._collect_graph(snapshot)
        records = {record.id: record for record in build_azure_inventory(snapshot)}
        self.assertEqual(records["u1"].created_by, "admin@contoso.com")
        self.assertEqual(records["sp1"].last_used, datetime(2026, 7, 1, 12, 0, tzinfo=timezone.utc))


if __name__ == "__main__":
    unittest.main()


def _obj(**attrs):
    return type("O", (), attrs)()


def _domain(display_name, kind, compartment_id, url):
    return _obj(
        id=f"ocid.domain.{display_name}", display_name=display_name, type=kind, compartment_id=compartment_id, url=url
    )


def _iso(moment):
    return moment.strftime("%Y-%m-%dT%H:%M:%S.000Z")


_PROD_USER_CREATED = (_OCI_NOW - timedelta(days=60)).replace(microsecond=0)
_PROD_LAST_LOGIN = (_OCI_NOW - timedelta(days=3)).replace(microsecond=0)
_PROD_DG_CREATED = (_OCI_NOW - timedelta(days=45)).replace(microsecond=0)
_D2_USER_CREATED = (_OCI_NOW - timedelta(days=90)).replace(microsecond=0)

_D2_URL = "https://d2.identity.example"
_PROD_URL = "https://prod.identity.example"


def _scim_user(ocid, name, created_by, *, login=None, mfa=None, console=True, api_keys=False, created=None):
    """A SCIM user the way oci.identity_domains returns it (extension attributes as SDK attributes)."""
    return _obj(
        id=f"scim-{name}",
        ocid=ocid,
        user_name=name,
        description=None,
        emails=[_obj(value=f"{name}@corp.com", primary=True)],
        meta=_obj(created=_iso(created or _PROD_USER_CREATED)),
        idcs_created_by=_obj(display=f"{created_by}@corp.com", value=f"ocid.user.{created_by}"),
        urn_ietf_params_scim_schemas_oracle_idcs_extension_user_state_user=(
            _obj(last_successful_login_date=_iso(login)) if login else None
        ),
        urn_ietf_params_scim_schemas_oracle_idcs_extension_mfa_user=_obj(mfa_status=mfa) if mfa else None,
        urn_ietf_params_scim_schemas_oracle_idcs_extension_capabilities_user=_obj(
            can_use_console_password=console, can_use_api_keys=api_keys
        ),
    )


def _scim_group(ocid, name, *members):
    return _obj(
        id=f"scim-{name}",
        ocid=ocid,
        display_name=name,
        description=None,
        members=[_obj(name=m, ocid=f"ocid.user.{m}", value=f"scim-{m}") for m in members] or None,
    )


def _scim_dynamic_group(ocid, name, rule):
    return _obj(
        id=f"scim-{name}",
        ocid=ocid,
        display_name=name,
        description=None,
        matching_rule=rule,
        meta=_obj(created=_iso(_PROD_DG_CREATED)),
    )


class _FakeScimClient:
    """Stand-in for oci.identity_domains.IdentityDomainsClient for one identity domain."""

    class _Resp:
        def __init__(self, data):
            self.data = data

    def __init__(self, users=(), groups=(), dynamic_groups=(), error=None):
        self.users, self.groups, self.dynamic_groups, self.error = (
            list(users),
            list(groups),
            list(dynamic_groups),
            error,
        )

    def _page(self, items, start_index):
        if self.error is not None:
            raise self.error
        return self._Resp(_obj(resources=items if (start_index or 1) == 1 else []))

    def list_users(self, attributes=None, count=None, start_index=None):
        return self._page(self.users, start_index)

    def list_groups(self, attributes=None, count=None, start_index=None):
        return self._page(self.groups, start_index)

    def list_dynamic_resource_groups(self, attributes=None, count=None, start_index=None):
        return self._page(self.dynamic_groups, start_index)


class _FakeNestedIdentityClient:
    """Tenancy with nested compartments and identity domains; records the compartment each call was given.

    tenancy                 Default domain (legacy API): alice/Administrators, bob/ProdOps, carol/DevOps
                            domain-2 (SECONDARY): dave/Ops, erin/Unused
    ├── prod                prod-domain (SECONDARY): frank/Domain_Administrators, grace/Readers, All Domain Users
    │   └── prod/app
    └── dev
    """

    class _Resp:
        def __init__(self, data):
            self.data = data
            self.next_page = None

    def __init__(self, root_error=None):
        self.calls = []
        self.root_error = root_error
        self.children = {
            "ocid.tenancy": [_obj(id="ocid.cmp.prod"), _obj(id="ocid.cmp.dev")],
            "ocid.cmp.prod": [_obj(id="ocid.cmp.app")],
            "ocid.cmp.app": [],
            "ocid.cmp.dev": [],
        }
        self.policies = {
            "ocid.tenancy": [
                _obj(
                    id="ocid.policy.root",
                    name="root",
                    compartment_id="ocid.tenancy",
                    statements=["Allow group Administrators to manage all-resources in tenancy"],
                )
            ],
            "ocid.cmp.prod": [
                _obj(
                    id="ocid.policy.prod",
                    name="prod",
                    compartment_id="ocid.cmp.prod",
                    statements=[
                        "Allow group 'Default'/'ProdOps' to manage instances in compartment prod",
                        "Allow group 'domain-2'/'Ops' to read instances in compartment prod",
                    ],
                )
            ],
            "ocid.cmp.app": [
                _obj(
                    id="ocid.policy.app",
                    name="app",
                    compartment_id="ocid.cmp.app",
                    statements=["Allow dynamic-group id ocid.dynamicgroup.dg to read objects in compartment prod:app"],
                )
            ],
            "ocid.cmp.dev": [
                _obj(
                    id="ocid.policy.dev",
                    name="dev",
                    compartment_id="ocid.cmp.dev",
                    statements=["Allow group DevOps to manage all-resources in compartment dev"],
                )
            ],
        }
        self.users = [
            _obj(id="ocid.user.alice", name="alice", time_created=_OCI_USER_CREATED),
            _obj(id="ocid.user.bob", name="bob", time_created=_OCI_USER_CREATED),
            _obj(id="ocid.user.carol", name="carol", time_created=_OCI_USER_CREATED),
        ]
        self.groups = [
            _obj(id="ocid.group.admins", name="Administrators"),
            _obj(id="ocid.group.prodops", name="ProdOps"),
            _obj(id="ocid.group.devops", name="DevOps"),
        ]
        self.dynamic_groups = [
            _obj(id="ocid.dynamicgroup.dg", name="instances-dg", matching_rule="x", time_created=_OCI_DG_CREATED),
            _obj(id="ocid.dynamicgroup.other", name="other-dg", matching_rule="y", time_created=_OCI_DG_CREATED),
        ]
        self.memberships = {
            "ocid.group.admins": [_obj(user_id="ocid.user.alice")],
            "ocid.group.prodops": [_obj(user_id="ocid.user.bob")],
            "ocid.group.devops": [_obj(user_id="ocid.user.carol")],
        }
        self.domains = {
            "ocid.tenancy": [
                _domain("Default", "DEFAULT", "ocid.tenancy", _DEFAULT_DOMAIN_URL),
                _domain("domain-2", "SECONDARY", "ocid.tenancy", _D2_URL),
            ],
            "ocid.cmp.prod": [_domain("prod-domain", "SECONDARY", "ocid.cmp.prod", _PROD_URL)],
            "ocid.cmp.app": [],
            "ocid.cmp.dev": [],
        }
        self.domain_clients = {
            # The Default domain mirrors the legacy listing (same OCIDs) and only adds idcsCreatedBy.
            _DEFAULT_DOMAIN_URL: _FakeScimClient(
                users=[_scim_user(u.id, u.name, "domain-admin") for u in self.users],
                groups=[_scim_group(g.id, g.name) for g in self.groups],
            ),
            _D2_URL: _FakeScimClient(
                users=[
                    _scim_user("ocid.user.dave", "dave", "d2-admin", created=_D2_USER_CREATED),
                    _scim_user("ocid.user.erin", "erin", "d2-admin", created=_D2_USER_CREATED),
                ],
                groups=[
                    _scim_group("ocid.group.d2ops", "Ops", "dave"),
                    _scim_group("ocid.group.d2unused", "Unused", "erin"),
                ],
            ),
            _PROD_URL: _FakeScimClient(
                users=[
                    _scim_user("ocid.user.frank", "frank", "prod-admin", login=_PROD_LAST_LOGIN, mfa="ENROLLED"),
                    _scim_user("ocid.user.grace", "grace", "prod-admin", console=False, api_keys=True),
                ],
                groups=[
                    _scim_group("ocid.group.proddomainadmins", "Domain_Administrators", "frank"),
                    _scim_group("ocid.group.prodall", "All Domain Users"),
                    _scim_group("ocid.group.prodreaders", "Readers", "grace"),
                ],
                dynamic_groups=[
                    _scim_dynamic_group(
                        "ocid.dynamicgroup.prodinst", "prod-instances", "instance.compartment.id = 'prod'"
                    )
                ],
            ),
        }

    def _root(self, call, compartment_id):
        self.calls.append((call, compartment_id))
        if self.root_error is not None and compartment_id == "ocid.tenancy":
            raise self.root_error

    def list_users(self, compartment_id, page=None):
        self._root("list_users", compartment_id)
        return self._Resp(self.users)

    def list_groups(self, compartment_id, page=None):
        self._root("list_groups", compartment_id)
        return self._Resp(self.groups)

    def list_dynamic_groups(self, compartment_id, page=None):
        self._root("list_dynamic_groups", compartment_id)
        return self._Resp(self.dynamic_groups)

    def list_compartments(self, compartment_id, page=None):
        self._root("list_compartments", compartment_id)
        return self._Resp(self.children[compartment_id])

    def list_policies(self, compartment_id, page=None):
        self._root("list_policies", compartment_id)
        return self._Resp(self.policies[compartment_id])

    def list_domains(self, compartment_id, page=None):
        self._root("list_domains", compartment_id)
        return self._Resp(self.domains[compartment_id])

    def list_user_group_memberships(self, compartment_id, group_id, page=None):
        self._root("list_user_group_memberships", compartment_id)
        self.calls[-1] = ("list_user_group_memberships", group_id)
        return self._Resp(self.memberships[group_id])


def _qualified(group):
    return f"{group.get('domain') or 'Default'}/{group['name']}"


class TestOciCompartmentScope(unittest.TestCase):
    def _collect(self, **options):
        client = _FakeNestedIdentityClient(root_error=options.pop("root_error", None))
        collector = get_collector(
            "oci", tenancy_id="ocid.tenancy", client=client, identity_domains_clients=client.domain_clients, **options
        )
        return collector.collect(), client

    # ------------------------------------------------------------ policies
    def test_tenancy_scope_walks_nested_compartments_for_policies(self):
        snapshot, _ = self._collect()
        self.assertEqual({p["name"] for p in snapshot["policies"]}, {"root", "prod", "app", "dev"})

    def test_compartment_scope_collects_policies_from_its_subtree_only(self):
        snapshot, client = self._collect(compartment_id="ocid.cmp.prod")
        self.assertEqual({p["name"] for p in snapshot["policies"]}, {"prod", "app"})
        listed = [cid for call, cid in client.calls if call == "list_policies"]
        self.assertEqual(sorted(listed), ["ocid.cmp.app", "ocid.cmp.prod"])

    def test_compartment_scope_is_recorded_alongside_tenancy(self):
        snapshot, _ = self._collect(compartment_id="ocid.cmp.prod")
        self.assertEqual(snapshot["account_id"], "ocid.tenancy")
        self.assertEqual(snapshot["compartment_id"], "ocid.cmp.prod")

    # ---------------------------------------------------- identity domains
    def test_tenancy_scope_collects_identity_domains_from_every_compartment(self):
        snapshot, client = self._collect()
        self.assertIsNone(snapshot["compartment_id"])
        names = sorted(u["name"] for u in snapshot["users"])
        self.assertEqual(names, ["alice", "bob", "carol", "dave", "erin", "frank", "grace"])
        self.assertEqual(
            sorted(_qualified(g) for g in snapshot["groups"]),
            [
                "Default/Administrators",
                "Default/DevOps",
                "Default/ProdOps",
                "domain-2/Ops",
                "domain-2/Unused",
                "prod-domain/All Domain Users",
                "prod-domain/Domain_Administrators",
                "prod-domain/Readers",
            ],
        )
        self.assertEqual(
            sorted(d["name"] for d in snapshot["dynamicGroups"]), ["instances-dg", "other-dg", "prod-instances"]
        )
        self.assertEqual(snapshot["groupMemberships"]["domain-2/Ops"], ["dave"])
        listed = sorted(cid for call, cid in client.calls if call == "list_domains")
        self.assertEqual(listed, ["ocid.cmp.app", "ocid.cmp.dev", "ocid.cmp.prod", "ocid.tenancy"])

    def test_compartment_scope_includes_the_identity_domain_inside_the_compartment(self):
        snapshot, _ = self._collect(compartment_id="ocid.cmp.prod")
        self.assertEqual(
            sorted(u["name"] for u in snapshot["users"] if u.get("domain") == "prod-domain"), ["frank", "grace"]
        )
        self.assertEqual(
            [g["name"] for g in snapshot["groups"] if g.get("domain") == "prod-domain"],
            ["Domain_Administrators", "All Domain Users", "Readers"],
        )
        self.assertEqual(
            [d["name"] for d in snapshot["dynamicGroups"] if d.get("domain") == "prod-domain"], ["prod-instances"]
        )
        self.assertEqual(snapshot["groupMemberships"]["prod-domain/Domain_Administrators"], ["frank"])
        self.assertEqual(snapshot["groupMemberships"]["prod-domain/All Domain Users"], [])
        self.assertEqual(snapshot["groupMemberships"]["prod-domain/Readers"], ["grace"])

    def test_compartment_scope_keeps_root_identities_only_when_a_scoped_policy_references_them(self):
        snapshot, client = self._collect(compartment_id="ocid.cmp.prod")
        root_users = sorted(u["name"] for u in snapshot["users"] if u.get("domain") != "prod-domain")
        self.assertEqual(root_users, ["bob", "dave"])
        root_groups = sorted(_qualified(g) for g in snapshot["groups"] if g.get("domain") != "prod-domain")
        self.assertEqual(root_groups, ["Default/ProdOps", "domain-2/Ops"])
        self.assertEqual(
            [d["name"] for d in snapshot["dynamicGroups"] if d.get("domain") != "prod-domain"], ["instances-dg"]
        )
        self.assertEqual(snapshot["groupMemberships"]["ProdOps"], ["bob"])
        self.assertEqual(snapshot["groupMemberships"]["domain-2/Ops"], ["dave"])
        self.assertNotIn("domain-2/Unused", snapshot["groupMemberships"])
        # Legacy memberships are only fetched for the root groups kept in scope.
        fetched = [gid for call, gid in client.calls if call == "list_user_group_memberships"]
        self.assertEqual(fetched, ["ocid.group.prodops"])

    def test_compartment_scope_still_lists_identities_from_the_tenancy_root(self):
        # OCI keeps users/groups/dynamic groups in the root compartment only; a
        # child compartment OCID is rejected by those list calls.
        _, client = self._collect(compartment_id="ocid.cmp.prod")
        for call in ("list_users", "list_groups", "list_dynamic_groups"):
            self.assertIn((call, "ocid.tenancy"), client.calls)

    def test_default_domain_identities_come_from_the_legacy_listing_without_duplicates(self):
        snapshot, _ = self._collect()
        ids = [u["id"] for u in snapshot["users"]]
        self.assertEqual(len(ids), len(set(ids)))
        alice = next(u for u in snapshot["users"] if u["name"] == "alice")
        self.assertIsNone(alice.get("domain"))
        self.assertEqual(
            alice["idcsCreatedBy"], {"display": "domain-admin@corp.com", "value": "ocid.user.domain-admin"}
        )
        self.assertEqual(sum(1 for g in snapshot["groups"] if g["name"] == "Administrators"), 1)

    def test_domain_user_lifecycle_fields_match_the_legacy_shape(self):
        snapshot, _ = self._collect(compartment_id="ocid.cmp.prod")
        frank = next(u for u in snapshot["users"] if u["name"] == "frank")
        self.assertEqual(frank["id"], "ocid.user.frank")
        self.assertEqual(frank["domain"], "prod-domain")
        self.assertEqual(frank["email"], "frank@corp.com")
        self.assertEqual(frank["timeCreated"], _PROD_USER_CREATED)
        self.assertEqual(frank["lastSuccessfulLoginTime"], _PROD_LAST_LOGIN)
        self.assertIs(frank["isMfaActivated"], True)
        self.assertEqual(frank["capabilities"], {"canUseConsolePassword": True, "canUseApiKeys": False})
        self.assertEqual(frank["idcsCreatedBy"], {"display": "prod-admin@corp.com", "value": "ocid.user.prod-admin"})
        grace = next(u for u in snapshot["users"] if u["name"] == "grace")
        self.assertIsNone(grace["lastSuccessfulLoginTime"])
        self.assertIs(grace["isMfaActivated"], False)
        prod_dg = next(d for d in snapshot["dynamicGroups"] if d["name"] == "prod-instances")
        self.assertEqual(prod_dg["id"], "ocid.dynamicgroup.prodinst")
        self.assertEqual(prod_dg["matching-rule"], "instance.compartment.id = 'prod'")
        self.assertEqual(prod_dg["timeCreated"], _PROD_DG_CREATED)

    def test_domain_identities_feed_the_identity_inventory(self):
        from cloudsplaining.identity_inventory.oci import build_inventory

        snapshot, _ = self._collect(compartment_id="ocid.cmp.prod")
        records = {r.name: r for r in build_inventory(snapshot)}
        self.assertEqual(records["frank"].classification, "human")
        self.assertEqual(records["frank"].created_by, "prod-admin@corp.com")
        self.assertEqual(records["grace"].classification, "machine")
        self.assertEqual(records["prod-instances"].classification, "machine")

    def test_domain_identities_round_trip_through_the_engine(self):
        from cloudsplaining.multicloud.oci.engine import OciProvider

        snapshot, _ = self._collect(compartment_id="ocid.cmp.prod")
        model = OciProvider().scan(snapshot)
        self.assertEqual(model.users["ocid.user.frank"].groups, ["prod-domain/Domain_Administrators"])
        self.assertEqual(model.users["ocid.user.dave"].groups, ["domain-2/Ops"])
        self.assertEqual(sorted(model.groups["ocid.group.d2ops"].customer_managed_policies.values()), ["prod"])

    # ------------------------------------------------------------- failures
    def test_compartment_scope_survives_an_unreadable_tenancy_root(self):
        with self.assertLogs("cloudsplaining.multicloud.collectors.oci", level="WARNING"):
            snapshot, _ = self._collect(
                compartment_id="ocid.cmp.prod", root_error=RuntimeError("NotAuthorizedOrNotFound")
            )
        self.assertEqual(sorted(u["name"] for u in snapshot["users"]), ["frank", "grace"])
        self.assertEqual({p["name"] for p in snapshot["policies"]}, {"prod", "app"})

    def test_tenancy_scope_does_not_hide_an_unreadable_root(self):
        with self.assertRaises(RuntimeError):
            self._collect(root_error=RuntimeError("NotAuthorizedOrNotFound"))

    def test_a_failing_identity_domain_is_skipped_not_fatal(self):
        client = _FakeNestedIdentityClient()
        client.domain_clients[_D2_URL] = _FakeScimClient(error=RuntimeError("boom"))
        collector = get_collector(
            "oci", tenancy_id="ocid.tenancy", client=client, identity_domains_clients=client.domain_clients
        )
        with self.assertLogs("cloudsplaining.multicloud.collectors.oci", level="WARNING"):
            snapshot = collector.collect()
        names = {u["name"] for u in snapshot["users"]}
        self.assertIn("frank", names)
        self.assertIn("alice", names)
        self.assertNotIn("dave", names)


class TestOciAuditCompartments(unittest.TestCase):
    def test_audit_events_are_queried_in_the_compartment_that_hosts_each_identity(self):
        # CreateUser / CreateDynamicGroup events for an identity domain are logged in the
        # compartment the domain lives in, so each identity's window must be queried there.
        audit = _FakeAuditClient()
        client = _FakeNestedIdentityClient()
        get_collector(
            "oci",
            tenancy_id="ocid.tenancy",
            client=client,
            identity_domains_clients=client.domain_clients,
            audit_client=audit,
            compartment_id="ocid.cmp.prod",
        ).collect()

        def covered(compartment_id, moment):
            return any(c == compartment_id and s <= moment <= e for c, s, e in audit.calls)

        self.assertTrue(covered("ocid.tenancy", _OCI_USER_CREATED))  # bob: Default domain, kept via ProdOps
        self.assertTrue(covered("ocid.tenancy", _D2_USER_CREATED))  # dave: domain-2 lives in the root
        self.assertTrue(covered("ocid.tenancy", _OCI_DG_CREATED))  # instances-dg
        self.assertTrue(covered("ocid.cmp.prod", _PROD_USER_CREATED))  # frank, grace: prod-domain
        self.assertTrue(covered("ocid.cmp.prod", _PROD_DG_CREATED))  # prod-instances
        self.assertFalse(covered("ocid.tenancy", _PROD_USER_CREATED))
        self.assertFalse(covered("ocid.cmp.prod", _OCI_USER_CREATED))
        self.assertEqual({c for c, _, _ in audit.calls}, {"ocid.tenancy", "ocid.cmp.prod"})
