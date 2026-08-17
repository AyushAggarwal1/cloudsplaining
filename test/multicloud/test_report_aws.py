import json
import unittest

from cloudsplaining.multicloud.analysis import CATEGORY_ORDER
from cloudsplaining.multicloud.gcp.engine import GcpProvider
from cloudsplaining.multicloud.oci.engine import OciProvider
from cloudsplaining.multicloud.provider import get_provider
from cloudsplaining.multicloud.report_aws import managed_policies_key, render
from cloudsplaining.shared.exclusions import Exclusions

_TOP_LEVEL = (
    "groups",
    "users",
    "roles",
    "gcp_managed_policies",
    "customer_managed_policies",
    "inline_policies",
    "exclusions",
    "links",
)


class TestReportAws(unittest.TestCase):
    def test_top_level_matches_aws_shape(self):
        model = GcpProvider().scan({"bindings": [{"role": "roles/owner", "members": ["user:a@b.com"]}]})
        report = render(model)
        for key in _TOP_LEVEL:
            self.assertIn(key, report)
        self.assertEqual(report["links"], {})

    def test_account_id_is_first_top_level_key(self):
        model = GcpProvider().scan({"bindings": [{"role": "roles/owner", "members": ["user:a@b.com"]}]})
        model.account_id = "demo-project"
        report = render(model)
        self.assertEqual(next(iter(report)), "account_id")
        self.assertEqual(report["account_id"], "demo-project")
        # json.dumps preserves insertion order, so account_id is line 1 of the payload.
        self.assertIn('"account_id"', json.dumps(report, indent=2).splitlines()[1])

    def test_policy_entry_has_all_categories(self):
        model = OciProvider().scan(["Allow group A to manage all-resources in tenancy"])
        report = render(model)
        policy = next(iter(report["customer_managed_policies"].values()))
        for field in ("PolicyName", "PolicyId", "AttachmentCount", "AttachedTo", "is_excluded"):
            self.assertIn(field, policy)
        for category in CATEGORY_ORDER:
            self.assertIn(category, policy)
            self.assertEqual(set(policy[category]), {"severity", "description", "findings"})

    def test_privilege_escalation_uses_type_actions_shape(self):
        model = GcpProvider().scan(
            {
                "customRoles": [
                    {"name": "projects/p/roles/r", "includedPermissions": ["resourcemanager.projects.setIamPolicy"]}
                ]
            }
        )
        report = render(model)
        pe = report["customer_managed_policies"]["projects/p/roles/r"]["PrivilegeEscalation"]
        self.assertEqual(pe["severity"], "critical")
        self.assertIn("type", pe["findings"][0])
        self.assertIn("actions", pe["findings"][0])

    def test_identity_entry_references_policies(self):
        model = GcpProvider().scan(
            {
                "predefinedRoles": [
                    {"name": "roles/owner", "includedPermissions": ["resourcemanager.projects.setIamPolicy"]}
                ],
                "bindings": [{"role": "roles/owner", "members": ["user:a@b.com"]}],
            }
        )
        report = render(model)
        user = next(iter(report["users"].values()))
        self.assertIn("roles/owner", user[managed_policies_key("gcp")])

    def test_exclusions_set_is_excluded(self):
        model = GcpProvider().scan(
            {"customRoles": [{"name": "AdministratorAccess", "includedPermissions": ["storage.objects.get"]}]}
        )
        exclusions = Exclusions({"policies": ["AdministratorAccess"], "roles": [], "users": [], "groups": []})
        report = render(model, exclusions)
        policy = report["customer_managed_policies"]["AdministratorAccess"]
        self.assertTrue(policy["is_excluded"])

    def test_serializable(self):
        model = get_provider("oci").scan(["Allow group A to manage all-resources in tenancy"])
        json.dumps(render(model), default=str)  # must not raise


if __name__ == "__main__":
    unittest.main()
