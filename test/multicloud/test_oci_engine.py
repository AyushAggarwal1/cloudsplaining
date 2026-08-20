import unittest

from cloudsplaining.multicloud.model import GROUP
from cloudsplaining.multicloud.oci.engine import OciProvider
from cloudsplaining.multicloud.oci.parser import parse_statement


def _cat(policy, name):
    return policy.categories.get(name, {"findings": [], "severity": "none"})


class TestOciParser(unittest.TestCase):
    def test_parse_basic(self):
        s = parse_statement("Allow group Admins to manage all-resources in tenancy")
        self.assertEqual(s.subject_type, "group")
        self.assertEqual(s.subject, "Admins")
        self.assertEqual(s.verb, "manage")
        self.assertTrue(s.is_tenancy)

    def test_parse_invalid_returns_none(self):
        self.assertIsNone(parse_statement("not a policy statement"))


class TestOciEngine(unittest.TestCase):
    def setUp(self):
        self.provider = OciProvider()

    def test_manage_all_resources_tenancy_critical(self):
        model = self.provider.scan(["Allow group Admins to manage all-resources in tenancy"])
        policy = next(iter(model.policies.values()))
        self.assertEqual(_cat(policy, "PrivilegeEscalation")["severity"], "critical")

    def test_any_user_is_public(self):
        model = self.provider.scan(["Allow any-user to manage buckets in tenancy"])
        policy = next(iter(model.policies.values()))
        self.assertTrue(_cat(policy, "PublicAccess")["findings"])

    def test_scan_reads_account_id_from_snapshot(self):
        model = self.provider.scan({"account_id": "ocid1.tenancy.oc1..demo", "policies": []})
        self.assertEqual(model.account_id, "ocid1.tenancy.oc1..demo")
        # Pasted statement lists carry no account scope.
        statements_only = self.provider.scan(["Allow group Admins to manage all-resources in tenancy"])
        self.assertEqual(statements_only.account_id, "")

    def test_policy_type_from_compartment_id(self):
        model = self.provider.scan(
            {
                "policies": [
                    {"id": "p1", "name": "root", "compartmentId": "ocid1.tenancy.oc1..abc", "statements": []},
                    {"id": "p2", "name": "child", "compartmentId": "ocid1.compartment.oc1..def", "statements": []},
                    {"id": "p3", "name": "pasted", "statements": []},
                ]
            }
        )
        self.assertEqual(model.policies["p1"].metadata["policyType"], "tenancy")
        self.assertEqual(model.policies["p2"].metadata["policyType"], "compartment")
        # No compartment information -> assume the narrower scope.
        self.assertEqual(model.policies["p3"].metadata["policyType"], "compartment")

    def test_condition_suppresses_data_exfiltration(self):
        model = self.provider.scan(["Allow group X to read buckets in tenancy where request.region = 'x'"])
        policy = next(iter(model.policies.values()))
        self.assertFalse(_cat(policy, "DataExfiltration")["findings"])

    def test_statement_subject_attaches_policy(self):
        model = self.provider.scan(
            [{"name": "p1", "statements": ["Allow group Admins to manage all-resources in tenancy"]}]
        )
        self.assertIn("Admins", model.policies["p1"].attached_to["groups"])
        group = self.provider._find_by_name(model, GROUP, "Admins")
        self.assertIsNotNone(group)
        self.assertIn("p1", group.permission_sets.values())

    def test_dynamic_group_is_group_with_dynamic_group_kind(self):
        model = self.provider.scan(
            {
                "dynamicGroups": [{"id": "dg1", "name": "Instances"}],
                "policies": [
                    {
                        "name": "p",
                        "statements": ["Allow dynamic-group Instances to use instance-family in compartment c"],
                    }
                ],
            }
        )
        dg = model.get_principal(GROUP, "dg1")
        self.assertIsNotNone(dg)
        self.assertEqual(dg.metadata.get("provider_kind"), "dynamic_group")
        self.assertIn("p", dg.permission_sets.values())

    def test_synthesized_dynamic_group_subject_is_group(self):
        model = self.provider.scan(["Allow dynamic-group Runners to use instance-family in compartment c"])
        dg = self.provider._find_by_name(model, GROUP, "Runners")
        self.assertIsNotNone(dg)
        self.assertEqual(dg.metadata.get("provider_kind"), "dynamic_group")


if __name__ == "__main__":
    unittest.main()
