import unittest

from cloudsplaining.multicloud.model import CUSTOMER, GROUP, ROLE
from cloudsplaining.multicloud.oci.engine import OciProvider
from cloudsplaining.multicloud.oci.parser import parse_statement, parse_subject, qualified_name


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

    def test_qualified_name_strips_quotes_from_domain_form(self):
        self.assertEqual(qualified_name("'Default'/'ciem-accuknox'"), "Default/ciem-accuknox")

    def test_qualified_name_keeps_unquoted_domain_form(self):
        self.assertEqual(qualified_name("Sales/Analysts"), "Sales/Analysts")

    def test_qualified_name_defaults_bare_name_to_default_domain(self):
        self.assertEqual(qualified_name("Admins"), "Default/Admins")

    def test_qualified_name_uses_explicit_domain_for_bare_name(self):
        self.assertEqual(qualified_name("Analysts", domain="Sales"), "Sales/Analysts")

    def test_parse_subject_id_reference(self):
        ref = parse_subject("id ocid1.group.oc1..abc")
        self.assertEqual(ref.id, "ocid1.group.oc1..abc")
        self.assertIsNone(ref.name)

    def test_parse_subject_name_reference_is_qualified(self):
        ref = parse_subject("'Default'/'Admins'")
        self.assertIsNone(ref.id)
        self.assertEqual(ref.name, "Default/Admins")

    def test_statement_subject_ref_is_qualified(self):
        s = parse_statement("Allow group 'Default'/'Admins' to manage all-resources in tenancy")
        self.assertEqual(s.subject, "'Default'/'Admins'")
        self.assertEqual(s.subject_ref.name, "Default/Admins")


class TestOciEngine(unittest.TestCase):
    def setUp(self):
        self.provider = OciProvider()

    def test_manage_all_resources_tenancy_critical(self):
        model = self.provider.scan(["Allow group Admins to manage all-resources in tenancy"])
        policy = next(iter(model.policies.values()))
        self.assertEqual(policy.kind, CUSTOMER)
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

    def test_condition_suppresses_data_exfiltration(self):
        model = self.provider.scan(["Allow group X to read buckets in tenancy where request.region = 'x'"])
        policy = next(iter(model.policies.values()))
        self.assertFalse(_cat(policy, "DataExfiltration")["findings"])

    def test_statement_subject_attaches_policy(self):
        model = self.provider.scan(
            [{"name": "p1", "statements": ["Allow group Admins to manage all-resources in tenancy"]}]
        )
        self.assertIn("Default/Admins", model.policies["p1"].attached_to["groups"])
        group = self.provider._find_by_name(model, GROUP, "Admins")
        self.assertIsNotNone(group)
        self.assertIn("p1", group.customer_managed_policies.values())

    def test_dynamic_group_subject_is_role(self):
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
        self.assertIsNotNone(model.get_principal(ROLE, "dg1"))
        self.assertIn("p", model.get_principal(ROLE, "dg1").customer_managed_policies.values())

    # ---- identity-domain-qualified naming: every group / dynamic group is "<domain>/<name>"
    def test_listed_group_is_named_domain_slash_name(self):
        model = self.provider.scan({"groups": [{"id": "g1", "name": "Admins"}]})
        self.assertEqual(model.groups["g1"].name, "Default/Admins")

    def test_listed_group_uses_its_own_domain(self):
        model = self.provider.scan({"groups": [{"id": "g1", "name": "Analysts", "domain": "Sales"}]})
        self.assertEqual(model.groups["g1"].name, "Sales/Analysts")

    def test_listed_dynamic_group_is_named_domain_slash_name(self):
        model = self.provider.scan({"dynamicGroups": [{"id": "dg1", "name": "Instances"}]})
        self.assertEqual(model.roles["dg1"].name, "Default/Instances")

    def test_domain_qualified_subject_resolves_to_listed_group(self):
        model = self.provider.scan(
            {
                "groups": [{"id": "g1", "name": "ciem-accuknox"}],
                "policies": [
                    {
                        "id": "p1",
                        "name": "ciem-accuknox",
                        "statements": ["Allow group 'Default'/'ciem-accuknox' to read all-resources in tenancy"],
                    }
                ],
            }
        )
        self.assertEqual(list(model.groups), ["g1"])
        self.assertIn("p1", model.groups["g1"].customer_managed_policies)
        self.assertEqual(model.policies["p1"].attached_to["groups"], ["Default/ciem-accuknox"])

    def test_bare_subject_resolves_to_listed_group(self):
        model = self.provider.scan(
            {
                "groups": [{"id": "g1", "name": "Admins"}],
                "policies": [
                    {"id": "p1", "name": "p", "statements": ["Allow group Admins to manage all-resources in tenancy"]}
                ],
            }
        )
        self.assertEqual(list(model.groups), ["g1"])
        self.assertIn("p1", model.groups["g1"].customer_managed_policies)

    def test_group_id_subject_resolves_by_ocid(self):
        model = self.provider.scan(
            {
                "groups": [{"id": "ocid1.group.oc1..g1", "name": "Admins"}],
                "policies": [
                    {
                        "id": "p1",
                        "name": "p",
                        "statements": ["Allow group id ocid1.group.oc1..g1 to manage all-resources in tenancy"],
                    }
                ],
            }
        )
        self.assertEqual(list(model.groups), ["ocid1.group.oc1..g1"])
        self.assertIn("p1", model.groups["ocid1.group.oc1..g1"].customer_managed_policies)

    def test_domain_qualified_dynamic_group_subject_resolves_to_listed_role(self):
        model = self.provider.scan(
            {
                "dynamicGroups": [{"id": "dg1", "name": "Instances"}],
                "policies": [
                    {
                        "id": "p1",
                        "name": "p",
                        "statements": [
                            "Allow dynamic-group 'Default'/'Instances' to use instance-family in compartment c"
                        ],
                    }
                ],
            }
        )
        self.assertEqual(list(model.roles), ["dg1"])
        self.assertIn("p1", model.roles["dg1"].customer_managed_policies)

    def test_membership_key_resolves_to_qualified_group(self):
        model = self.provider.scan(
            {
                "users": [{"id": "u1", "name": "alice"}],
                "groups": [{"id": "g1", "name": "Admins"}],
                "groupMemberships": {"Admins": ["alice"]},
            }
        )
        self.assertEqual(model.users["u1"].groups, ["Default/Admins"])

    def test_unlisted_qualified_subject_creates_one_canonical_group(self):
        model = self.provider.scan(["Allow group 'Sales'/'Analysts' to read buckets in tenancy"])
        self.assertEqual(list(model.groups), ["group:Sales/Analysts"])
        self.assertEqual(model.groups["group:Sales/Analysts"].name, "Sales/Analysts")


if __name__ == "__main__":
    unittest.main()
