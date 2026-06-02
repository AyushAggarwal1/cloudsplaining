import unittest

from cloudsplaining.multicloud.collectors import get_collector
from cloudsplaining.multicloud.collectors.base import Collector, CollectorDependencyError


class _FakeIdentityClient:
    """Minimal stand-in for oci.identity.IdentityClient."""

    class _Resp:
        def __init__(self, data):
            self.data = data
            self.next_page = None

    def __init__(self):
        self._user = type("U", (), {"id": "ocid.user.alice", "name": "alice", "description": None})()
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
        return self._Resp([])

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


if __name__ == "__main__":
    unittest.main()
