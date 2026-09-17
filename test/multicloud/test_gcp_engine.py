import unittest

from cloudsplaining.multicloud.gcp.engine import GcpProvider
from cloudsplaining.multicloud.model import CUSTOMER, MANAGED, USER


def _cat(policy, name):
    return policy.categories.get(name, {"findings": [], "severity": "none"})


class TestGcpEngine(unittest.TestCase):
    def setUp(self):
        self.provider = GcpProvider()

    def test_custom_role_setiampolicy_is_privesc(self):
        model = self.provider.scan(
            {"customRoles": [{"name": "projects/p/roles/r", "includedPermissions": ["storage.buckets.setIamPolicy"]}]}
        )
        policy = model.policies["projects/p/roles/r"]
        self.assertEqual(policy.kind, CUSTOMER)
        self.assertTrue(_cat(policy, "PrivilegeEscalation")["findings"])

    def test_scan_reads_account_id_from_snapshot(self):
        model = self.provider.scan({"account_id": "demo-project", "bindings": []})
        self.assertEqual(model.account_id, "demo-project")
        # Bare role/binding lists carry no account scope.
        self.assertEqual(self.provider.scan([]).account_id, "")

    def test_predefined_role_goes_to_managed(self):
        model = self.provider.scan(
            {
                "predefinedRoles": [
                    {"name": "roles/owner", "includedPermissions": ["resourcemanager.projects.setIamPolicy"]}
                ],
                "bindings": [{"role": "roles/owner", "members": ["user:a@b.com"], "resource": "projects/p"}],
            }
        )
        self.assertEqual(model.policies["roles/owner"].kind, MANAGED)

    def test_public_member_flagged_and_attached(self):
        model = self.provider.scan(
            {
                "bindings": [
                    {"role": "roles/storage.objectViewer", "members": ["allUsers"], "resource": "projects/p/buckets/x"}
                ]
            }
        )
        policy = model.policies["roles/storage.objectViewer"]
        self.assertEqual(_cat(policy, "PublicAccess")["severity"], "critical")

    def test_member_types_route_to_collections(self):
        model = self.provider.scan(
            {
                "bindings": [
                    {
                        "role": "roles/viewer",
                        "members": ["user:a@b.com", "group:g@b.com", "serviceAccount:sa@p.iam.gserviceaccount.com"],
                        "resource": "projects/p",
                    }
                ]
            }
        )
        self.assertIsNotNone(model.get_principal(USER, "user:a@b.com"))
        self.assertEqual(len(model.groups), 1)
        # service accounts are principals (identities), not roles — they land in users
        self.assertEqual(len(model.users), 2)  # user:a@b.com + serviceAccount:sa@...
        self.assertEqual(len(model.roles), 0)

    def test_service_account_has_service_account_provider_kind(self):
        model = self.provider.scan(
            {
                "serviceAccounts": [
                    {"email": "my-sa@proj.iam.gserviceaccount.com", "uniqueId": "123", "displayName": "My SA"}
                ],
                "bindings": [
                    {
                        "role": "roles/storage.admin",
                        "members": ["serviceAccount:my-sa@proj.iam.gserviceaccount.com"],
                        "resource": "projects/p",
                    }
                ],
            }
        )
        sa = model.get_principal(USER, "serviceAccount:my-sa@proj.iam.gserviceaccount.com")
        self.assertIsNotNone(sa)
        self.assertEqual(sa.metadata.get("provider_kind"), "service_account")
        self.assertEqual(len(model.roles), 0)

    def test_binding_builds_attachment(self):
        model = self.provider.scan(
            {
                "customRoles": [{"name": "projects/p/roles/r", "includedPermissions": ["storage.objects.get"]}],
                "bindings": [{"role": "projects/p/roles/r", "members": ["user:a@b.com"], "resource": "projects/p"}],
            }
        )
        self.assertIn("a@b.com", model.policies["projects/p/roles/r"].attached_to["users"])


if __name__ == "__main__":
    unittest.main()
