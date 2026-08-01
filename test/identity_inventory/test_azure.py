import unittest
from datetime import datetime, timezone

from cloudsplaining.identity_inventory.azure import build_inventory
from cloudsplaining.identity_inventory.model import HUMAN, MACHINE


def _snapshot():
    return {
        "users": [
            {
                "id": "u1",
                "userPrincipalName": "jane@contoso.com",
                "displayName": "Jane Doe",
                "createdDateTime": "2025-08-01T00:00:00Z",
                "signInActivity": {
                    "lastSignInDateTime": "2026-07-30T00:00:00Z",
                    "lastNonInteractiveSignInDateTime": "2026-07-31T00:00:00Z",
                },
            },
            {"id": "u2", "userPrincipalName": "svc-scanner@contoso.com", "displayName": "Scanner"},
        ],
        "servicePrincipals": [
            {
                "id": "sp1",
                "appId": "app-123",
                "displayName": "deploy-pipeline",
                "servicePrincipalType": "Application",
                "createdDateTime": "2026-02-01T00:00:00Z",
            },
            {
                "id": "sp2",
                "appId": "app-456",
                "displayName": "vm-identity",
                "servicePrincipalType": "ManagedIdentity",
            },
        ],
        "groups": [{"id": "g1", "displayName": "Engineering"}],
    }


def _by_id(records, record_id):
    return next(r for r in records if r.id == record_id)


class TestAzureInventory(unittest.TestCase):
    def test_users_and_service_principals_inventoried_groups_skipped(self):
        records = build_inventory(_snapshot())
        self.assertEqual({r.id for r in records}, {"u1", "u2", "sp1", "sp2"})

    def test_user_is_human_with_lifecycle_fields(self):
        jane = _by_id(build_inventory(_snapshot()), "u1")
        self.assertEqual(jane.classification, HUMAN)
        self.assertEqual(jane.identity_type, "user")
        self.assertEqual(jane.name, "jane@contoso.com")
        self.assertEqual(jane.created_at, datetime(2025, 8, 1, tzinfo=timezone.utc))

    def test_user_last_used_is_max_of_sign_in_kinds(self):
        jane = _by_id(build_inventory(_snapshot()), "u1")
        self.assertEqual(jane.last_used, datetime(2026, 7, 31, tzinfo=timezone.utc))

    def test_machine_named_user_is_machine(self):
        self.assertEqual(_by_id(build_inventory(_snapshot()), "u2").classification, MACHINE)

    def test_service_principals_are_machine(self):
        records = build_inventory(_snapshot())
        self.assertEqual(_by_id(records, "sp1").classification, MACHINE)
        self.assertEqual(_by_id(records, "sp2").classification, MACHINE)
        self.assertEqual(_by_id(records, "sp1").identity_type, "service_principal")

    def test_sp_last_used_from_sign_in_activities_by_app_id(self):
        data = _snapshot()
        data["servicePrincipalSignInActivities"] = [
            {"appId": "app-123", "lastSignInActivity": {"lastSignInDateTime": "2026-07-20T00:00:00Z"}}
        ]
        sp = _by_id(build_inventory(data), "sp1")
        self.assertEqual(sp.last_used, datetime(2026, 7, 20, tzinfo=timezone.utc))

    def test_created_by_from_directory_audits(self):
        data = _snapshot()
        data["directoryAudits"] = [
            {
                "activityDisplayName": "Add user",
                "initiatedBy": {"user": {"userPrincipalName": "admin@contoso.com"}},
                "targetResources": [{"id": "u1"}],
            },
            {
                "activityDisplayName": "Add service principal",
                "initiatedBy": {"app": {"displayName": "Terraform"}},
                "targetResources": [{"id": "sp1"}],
            },
        ]
        records = build_inventory(data)
        self.assertEqual(_by_id(records, "u1").created_by, "admin@contoso.com")
        self.assertEqual(_by_id(records, "sp1").created_by, "Terraform")

    def test_unknowns_are_none(self):
        sp2 = _by_id(build_inventory(_snapshot()), "sp2")
        self.assertIsNone(sp2.created_at)
        self.assertIsNone(sp2.last_used)
        self.assertIsNone(sp2.created_by)


if __name__ == "__main__":
    unittest.main()
