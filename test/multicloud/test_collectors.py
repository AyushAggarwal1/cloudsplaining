import unittest
from datetime import datetime, timezone

from cloudsplaining.identity_inventory.azure import build_inventory as build_azure_inventory
from cloudsplaining.multicloud.collectors import get_collector
from cloudsplaining.multicloud.collectors.azure import AzureCollector
from cloudsplaining.multicloud.collectors.base import Collector, CollectorDependencyError


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
                "time_created": datetime(2025, 2, 1, tzinfo=timezone.utc),
                "last_successful_login_time": datetime(2026, 7, 1, tzinfo=timezone.utc),
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
                "time_created": datetime(2026, 3, 1, tzinfo=timezone.utc),
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
        self.assertEqual(user["timeCreated"], datetime(2025, 2, 1, tzinfo=timezone.utc))
        self.assertEqual(user["lastSuccessfulLoginTime"], datetime(2026, 7, 1, tzinfo=timezone.utc))
        self.assertIs(user["isMfaActivated"], False)
        self.assertEqual(user["email"], "alice@corp.com")
        self.assertEqual(user["capabilities"], {"canUseConsolePassword": False, "canUseApiKeys": True})
        dynamic_group = snapshot["dynamicGroups"][0]
        self.assertEqual(dynamic_group["timeCreated"], datetime(2026, 3, 1, tzinfo=timezone.utc))

    def test_oci_snapshot_feeds_identity_inventory(self):
        from cloudsplaining.identity_inventory.oci import build_inventory

        collector = get_collector("oci", tenancy_id="ocid.tenancy", client=_FakeIdentityClient())
        records = {r.name: r for r in build_inventory(collector.collect())}
        # alice: API keys, no console password, no MFA -> machine service account.
        self.assertEqual(records["alice"].classification, "machine")
        self.assertEqual(records["alice"].created_at, datetime(2025, 2, 1, tzinfo=timezone.utc))
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
