import json
import unittest

from cloudsplaining.multicloud.analysis import CATEGORY_ORDER
from cloudsplaining.multicloud.azure.engine import AzureProvider
from cloudsplaining.multicloud.gcp.engine import GcpProvider
from cloudsplaining.multicloud.oci.engine import OciProvider
from cloudsplaining.multicloud.provider import get_provider
from cloudsplaining.multicloud.serialize import permission_collection_key, render
from cloudsplaining.shared.exclusions import Exclusions

# Keys the old AWS-shaped report used that must no longer appear.
_REMOVED_KEYS = (
    "aws_managed_policies",
    "azure_managed_policies",
    "gcp_managed_policies",
    "oci_managed_policies",
    "customer_managed_policies",
    "inline_policies",
)


class TestPermissionCollectionKey(unittest.TestCase):
    def test_provider_native_keys(self):
        self.assertEqual(permission_collection_key("azure"), "roles")
        self.assertEqual(permission_collection_key("gcp"), "roles")
        self.assertEqual(permission_collection_key("oci"), "policies")


class TestSerializeShape(unittest.TestCase):
    def test_gcp_top_level_shape(self):
        model = GcpProvider().scan({"bindings": [{"role": "roles/owner", "members": ["user:a@b.com"]}]})
        report = render(model)
        for key in ("account_id", "provider", "groups", "users", "roles", "exclusions", "links"):
            self.assertIn(key, report)
        for key in _REMOVED_KEYS:
            self.assertNotIn(key, report)
        self.assertEqual(report["links"], {})

    def test_oci_top_level_shape(self):
        model = OciProvider().scan(["Allow group A to manage all-resources in tenancy"])
        report = render(model)
        for key in ("account_id", "provider", "groups", "users", "policies", "exclusions", "links"):
            self.assertIn(key, report)
        self.assertNotIn("roles", report)
        for key in _REMOVED_KEYS:
            self.assertNotIn(key, report)

    def test_account_id_is_first_top_level_key(self):
        model = GcpProvider().scan({"bindings": [{"role": "roles/owner", "members": ["user:a@b.com"]}]})
        model.account_id = "demo-project"
        report = render(model)
        self.assertEqual(next(iter(report)), "account_id")
        self.assertEqual(report["account_id"], "demo-project")
        # json.dumps preserves insertion order, so account_id is line 1 of the payload.
        self.assertIn('"account_id"', json.dumps(report, indent=2).splitlines()[1])


class TestRoleEntries(unittest.TestCase):
    def test_azure_role_entry_fields(self):
        model = AzureProvider().scan(
            {
                "roleDefinitions": [
                    {
                        "id": "owner",
                        "roleName": "Owner",
                        "roleType": "BuiltInRole",
                        "permissions": [{"actions": ["*"]}],
                    },
                    {
                        "id": "custom1",
                        "roleName": "MyCustom",
                        "roleType": "CustomRole",
                        "permissions": [{"actions": ["Microsoft.Storage/storageAccounts/read"]}],
                    },
                ]
            }
        )
        report = render(model)
        # Built-in and custom role definitions live in ONE `roles` collection.
        self.assertEqual(set(report["roles"]), {"owner", "custom1"})
        entry = report["roles"]["owner"]
        for field in ("RoleName", "RoleId", "roleType", "AttachmentCount", "AttachedTo", "is_excluded"):
            self.assertIn(field, entry)
        self.assertEqual(entry["RoleName"], "Owner")
        self.assertEqual(entry["roleType"], "BuiltInRole")
        self.assertEqual(report["roles"]["custom1"]["roleType"], "CustomRole")
        self.assertNotIn("PolicyName", entry)
        self.assertEqual(set(entry["AttachedTo"]), {"users", "groups"})
        for category in CATEGORY_ORDER:
            self.assertIn(category, entry)
            self.assertEqual(set(entry[category]), {"severity", "description", "findings"})

    def test_gcp_role_entry_fields(self):
        model = GcpProvider().scan(
            {
                "predefinedRoles": [
                    {"name": "roles/storage.admin", "includedPermissions": ["storage.buckets.setIamPolicy"]}
                ],
                "customRoles": [{"name": "projects/p/roles/r", "includedPermissions": ["storage.objects.get"]}],
            }
        )
        report = render(model)
        entry = report["roles"]["roles/storage.admin"]
        self.assertEqual(entry["RoleName"], "roles/storage.admin")
        self.assertEqual(entry["RoleId"], "roles/storage.admin")
        self.assertEqual(entry["roleType"], "predefined")
        self.assertIn("IncludedPermissions", entry)
        # public is always present on GCP role entries, even when empty.
        self.assertEqual(set(entry["AttachedTo"]), {"users", "groups", "public"})
        self.assertEqual(report["roles"]["projects/p/roles/r"]["roleType"], "custom")

    def test_oci_policy_entry_fields(self):
        model = OciProvider().scan(
            {
                "policies": [
                    {
                        "id": "p1",
                        "name": "AuditSCC",
                        "compartmentId": "ocid1.tenancy.oc1..abc",
                        "statements": ["Allow group AuditSecurity to read all-resources in tenancy"],
                    }
                ]
            }
        )
        report = render(model)
        entry = report["policies"]["p1"]
        for field in (
            "PolicyName",
            "PolicyId",
            "policyType",
            "statements",
            "GrantedAccess",
            "AttachmentCount",
            "AttachedTo",
            "is_excluded",
        ):
            self.assertIn(field, entry)
        self.assertEqual(entry["policyType"], "tenancy")
        self.assertNotIn("RoleName", entry)
        self.assertEqual(set(entry["AttachedTo"]), {"users", "groups"})

    def test_privilege_escalation_uses_type_actions_shape(self):
        model = GcpProvider().scan(
            {
                "customRoles": [
                    {"name": "projects/p/roles/r", "includedPermissions": ["resourcemanager.projects.setIamPolicy"]}
                ]
            }
        )
        report = render(model)
        pe = report["roles"]["projects/p/roles/r"]["PrivilegeEscalation"]
        self.assertEqual(pe["severity"], "critical")
        self.assertIn("type", pe["findings"][0])
        self.assertIn("actions", pe["findings"][0])


class TestPrincipalEntries(unittest.TestCase):
    def test_gcp_user_references_roles(self):
        model = GcpProvider().scan(
            {
                "predefinedRoles": [
                    {"name": "roles/owner", "includedPermissions": ["resourcemanager.projects.setIamPolicy"]}
                ],
                "bindings": [{"role": "roles/owner", "members": ["user:a@b.com"]}],
            }
        )
        report = render(model)
        user = report["users"]["user:a@b.com"]
        self.assertIn("roles/owner", user["roles"])
        self.assertEqual(user["provider_kind"], "user")
        for key in ("gcp_managed_policies", "customer_managed_policies", "inline_policies"):
            self.assertNotIn(key, user)

    def test_azure_service_principal_is_a_user(self):
        model = AzureProvider().scan({"servicePrincipals": [{"id": "sp1", "displayName": "ci"}]})
        report = render(model)
        self.assertIn("sp1", report["users"])
        self.assertEqual(report["users"]["sp1"]["provider_kind"], "service_principal")

    def test_oci_dynamic_group_is_a_group_with_policies_pointer(self):
        model = OciProvider().scan(
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
        report = render(model)
        self.assertIn("dg1", report["groups"])
        entry = report["groups"]["dg1"]
        self.assertEqual(entry["provider_kind"], "dynamic_group")
        self.assertIn("p", entry["policies"].values())


class TestExclusionsAndSerialization(unittest.TestCase):
    def test_exclusions_set_is_excluded(self):
        model = GcpProvider().scan(
            {"customRoles": [{"name": "AdministratorAccess", "includedPermissions": ["storage.objects.get"]}]}
        )
        exclusions = Exclusions({"policies": ["AdministratorAccess"], "roles": [], "users": [], "groups": []})
        report = render(model, exclusions)
        self.assertTrue(report["roles"]["AdministratorAccess"]["is_excluded"])

    def test_serializable(self):
        model = get_provider("oci").scan(["Allow group A to manage all-resources in tenancy"])
        json.dumps(render(model), default=str)  # must not raise


if __name__ == "__main__":
    unittest.main()
