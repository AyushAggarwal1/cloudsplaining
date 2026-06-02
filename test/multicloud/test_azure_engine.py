import unittest

from cloudsplaining.multicloud.azure.engine import AzureProvider
from cloudsplaining.multicloud.model import CUSTOMER, MANAGED, ROLE, USER


def _cat(policy, name):
    return policy.categories.get(name, {"findings": [], "severity": "none"})


class TestAzureEngine(unittest.TestCase):
    def setUp(self):
        self.provider = AzureProvider()

    def test_wildcard_role_is_service_wildcard_critical(self):
        model = self.provider.scan(
            [{"roleName": "superadmin", "roleType": "CustomRole", "assignableScopes": ["/"], "permissions": [{"actions": ["*"]}]}]
        )
        policy = next(iter(model.policies.values()))
        self.assertEqual(policy.kind, CUSTOMER)
        self.assertEqual(_cat(policy, "ServiceWildcard")["severity"], "critical")

    def test_builtin_role_goes_to_managed(self):
        model = self.provider.scan(
            {"roleDefinitions": [{"id": "owner", "roleName": "Owner", "roleType": "BuiltInRole", "permissions": [{"actions": ["*"]}]}]}
        )
        policy = model.policies["owner"]
        self.assertEqual(policy.kind, MANAGED)

    def test_not_actions_subtract_privesc(self):
        model = self.provider.scan(
            [{"roleName": "almost", "roleType": "CustomRole", "permissions": [{"actions": ["Microsoft.Authorization/*"], "notActions": ["Microsoft.Authorization/roleAssignments/write"]}]}]
        )
        policy = next(iter(model.policies.values()))
        privesc_actions = [a for f in _cat(policy, "PrivilegeEscalation")["findings"] for a in f["actions"]]
        self.assertNotIn("microsoft.authorization/roleassignments/write", privesc_actions)

    def test_assignment_builds_attachment_graph(self):
        model = self.provider.scan(
            {
                "users": [{"id": "u1", "userPrincipalName": "alice@x.com"}],
                "roleDefinitions": [{"id": "rd1", "roleName": "custom", "roleType": "CustomRole", "permissions": [{"actions": ["*"]}]}],
                "roleAssignments": [{"principalId": "u1", "principalType": "User", "roleDefinitionId": "rd1", "scope": "/subscriptions/x"}],
            }
        )
        user = model.get_principal(USER, "u1")
        self.assertIn("custom", user.customer_managed_policies.values())
        self.assertIn("alice@x.com", model.policies["rd1"].attached_to["users"])

    def test_service_principal_is_role(self):
        model = self.provider.scan({"servicePrincipals": [{"id": "sp1", "displayName": "ci"}]})
        self.assertIsNotNone(model.get_principal(ROLE, "sp1"))

    def test_group_membership_recorded(self):
        model = self.provider.scan(
            {
                "users": [{"id": "u1", "userPrincipalName": "bob@x.com"}],
                "groups": [{"id": "g1", "displayName": "devs"}],
                "groupMemberships": {"g1": ["u1"]},
            }
        )
        self.assertIn("devs", model.get_principal(USER, "u1").groups)


if __name__ == "__main__":
    unittest.main()
