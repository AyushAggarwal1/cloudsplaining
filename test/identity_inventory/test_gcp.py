import unittest
from datetime import datetime, timezone

from cloudsplaining.identity_inventory.gcp import build_inventory
from cloudsplaining.identity_inventory.model import HUMAN, MACHINE

SA_EMAIL = "ci-builder@proj.iam.gserviceaccount.com"


def _snapshot():
    return {
        "serviceAccounts": [{"email": SA_EMAIL, "uniqueId": "111", "displayName": "CI builder"}],
        "users": [
            {
                "primaryEmail": "dev@corp.com",
                "creationTime": "2024-08-01T00:00:00Z",
                "lastLoginTime": "2026-07-31T00:00:00Z",
            }
        ],
        "bindings": [
            {
                "role": "roles/viewer",
                "members": [
                    "user:extra@corp.com",
                    f"serviceAccount:{SA_EMAIL}",
                    "group:eng@corp.com",
                    "domain:corp.com",
                    "deleted:user:ghost@corp.com?uid=123",
                    "allUsers",
                ],
            }
        ],
    }


def _by_name(records, name):
    return next(r for r in records if r.name == name)


class TestGcpInventory(unittest.TestCase):
    def test_identities_inventoried_groups_domains_and_special_members_skipped(self):
        records = build_inventory(_snapshot())
        self.assertEqual({r.name for r in records}, {SA_EMAIL, "dev@corp.com", "extra@corp.com"})

    def test_service_account_is_machine(self):
        sa = _by_name(build_inventory(_snapshot()), SA_EMAIL)
        self.assertEqual(sa.classification, MACHINE)
        self.assertEqual(sa.identity_type, "service_account")
        self.assertEqual(sa.id, "111")

    def test_workspace_user_is_human_with_lifecycle_fields(self):
        dev = _by_name(build_inventory(_snapshot()), "dev@corp.com")
        self.assertEqual(dev.classification, HUMAN)
        self.assertEqual(dev.identity_type, "user")
        self.assertEqual(dev.created_at, datetime(2024, 8, 1, tzinfo=timezone.utc))
        self.assertEqual(dev.last_used, datetime(2026, 7, 31, tzinfo=timezone.utc))

    def test_binding_only_user_has_unknown_lifecycle(self):
        extra = _by_name(build_inventory(_snapshot()), "extra@corp.com")
        self.assertEqual(extra.classification, HUMAN)
        self.assertIsNone(extra.created_at)
        self.assertIsNone(extra.last_used)

    def test_binding_only_external_service_account_is_added(self):
        data = _snapshot()
        data["bindings"].append(
            {"role": "roles/editor", "members": ["serviceAccount:other@other-proj.iam.gserviceaccount.com"]}
        )
        sa = _by_name(build_inventory(data), "other@other-proj.iam.gserviceaccount.com")
        self.assertEqual(sa.classification, MACHINE)

    def test_create_time_on_service_account_is_used(self):
        data = _snapshot()
        data["serviceAccounts"][0]["createTime"] = "2026-06-15T00:00:00Z"
        sa = _by_name(build_inventory(data), SA_EMAIL)
        self.assertEqual(sa.created_at, datetime(2026, 6, 15, tzinfo=timezone.utc))

    def test_audit_log_entries_fill_created_at_and_created_by(self):
        data = _snapshot()
        data["auditLogEntries"] = [
            {
                "timestamp": "2026-06-01T00:00:00Z",
                "protoPayload": {
                    "methodName": "google.iam.admin.v1.CreateServiceAccount",
                    "authenticationInfo": {"principalEmail": "admin@corp.com"},
                    "response": {"email": SA_EMAIL},
                },
            }
        ]
        sa = _by_name(build_inventory(data), SA_EMAIL)
        self.assertEqual(sa.created_at, datetime(2026, 6, 1, tzinfo=timezone.utc))
        self.assertEqual(sa.created_by, "admin@corp.com")

    def test_policy_analyzer_activities_fill_last_used(self):
        data = _snapshot()
        data["serviceAccountActivities"] = [
            {
                "fullResourceName": f"//iam.googleapis.com/projects/proj/serviceAccounts/{SA_EMAIL}",
                "activity": {"lastAuthenticatedTime": "2026-07-15T00:00:00Z"},
            }
        ]
        sa = _by_name(build_inventory(data), SA_EMAIL)
        self.assertEqual(sa.last_used, datetime(2026, 7, 15, tzinfo=timezone.utc))


if __name__ == "__main__":
    unittest.main()
