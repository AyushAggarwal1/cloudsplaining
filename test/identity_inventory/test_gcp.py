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


class TestGcpUserAuditLifecycle(unittest.TestCase):
    """Audit logs substitute for the Workspace Admin SDK scope (admin.directory.user.readonly):
    any Admin Activity entry gives a user's last GCP activity, and the SetIamPolicy grant that
    first added the user is the created_at/created_by proxy."""

    def test_user_last_used_from_audit_activity(self):
        data = _snapshot()
        data["auditLogEntries"] = [
            {
                "timestamp": "2026-05-01T00:00:00Z",
                "protoPayload": {
                    "methodName": "v1.compute.instances.insert",
                    "authenticationInfo": {"principalEmail": "extra@corp.com"},
                },
            },
            {
                "timestamp": "2026-07-20T00:00:00Z",
                "protoPayload": {
                    "methodName": "storage.buckets.list",
                    "authenticationInfo": {"principalEmail": "extra@corp.com"},
                },
            },
        ]
        extra = _by_name(build_inventory(data), "extra@corp.com")
        self.assertEqual(extra.last_used, datetime(2026, 7, 20, tzinfo=timezone.utc))

    def test_user_last_used_is_newest_of_workspace_login_and_audit_activity(self):
        data = _snapshot()
        data["auditLogEntries"] = [
            {
                "timestamp": "2026-08-01T00:00:00Z",
                "protoPayload": {
                    "methodName": "storage.buckets.list",
                    "authenticationInfo": {"principalEmail": "dev@corp.com"},
                },
            }
        ]
        dev = _by_name(build_inventory(data), "dev@corp.com")
        self.assertEqual(dev.last_used, datetime(2026, 8, 1, tzinfo=timezone.utc))

    def test_set_iam_policy_grant_fills_created_at_and_created_by(self):
        data = _snapshot()
        data["auditLogEntries"] = [
            {
                "timestamp": "2026-04-10T00:00:00Z",
                "protoPayload": {
                    "methodName": "SetIamPolicy",
                    "authenticationInfo": {"principalEmail": "admin@corp.com"},
                    "serviceData": {
                        "policyDelta": {
                            "bindingDeltas": [
                                {"action": "ADD", "role": "roles/viewer", "member": "user:extra@corp.com"}
                            ]
                        }
                    },
                },
            }
        ]
        extra = _by_name(build_inventory(data), "extra@corp.com")
        self.assertEqual(extra.created_at, datetime(2026, 4, 10, tzinfo=timezone.utc))
        self.assertEqual(extra.created_by, "admin@corp.com")

    def test_earliest_grant_wins(self):
        data = _snapshot()
        grant = {
            "methodName": "SetIamPolicy",
            "authenticationInfo": {"principalEmail": "admin@corp.com"},
            "serviceData": {
                "policyDelta": {
                    "bindingDeltas": [{"action": "ADD", "role": "roles/viewer", "member": "user:extra@corp.com"}]
                }
            },
        }
        data["auditLogEntries"] = [
            {"timestamp": "2026-06-01T00:00:00Z", "protoPayload": grant},
            {"timestamp": "2026-03-01T00:00:00Z", "protoPayload": grant},
        ]
        extra = _by_name(build_inventory(data), "extra@corp.com")
        self.assertEqual(extra.created_at, datetime(2026, 3, 1, tzinfo=timezone.utc))

    def test_workspace_creation_time_wins_over_grant_proxy(self):
        data = _snapshot()
        data["auditLogEntries"] = [
            {
                "timestamp": "2026-04-10T00:00:00Z",
                "protoPayload": {
                    "methodName": "SetIamPolicy",
                    "authenticationInfo": {"principalEmail": "admin@corp.com"},
                    "serviceData": {
                        "policyDelta": {
                            "bindingDeltas": [{"action": "ADD", "role": "roles/viewer", "member": "user:dev@corp.com"}]
                        }
                    },
                },
            }
        ]
        dev = _by_name(build_inventory(data), "dev@corp.com")
        # Workspace creationTime is authoritative; the grant only supplies created_by.
        self.assertEqual(dev.created_at, datetime(2024, 8, 1, tzinfo=timezone.utc))
        self.assertEqual(dev.created_by, "admin@corp.com")

    def test_remove_only_deltas_do_not_fill_creation(self):
        data = _snapshot()
        data["auditLogEntries"] = [
            {
                "timestamp": "2026-04-10T00:00:00Z",
                "protoPayload": {
                    "methodName": "SetIamPolicy",
                    "authenticationInfo": {"principalEmail": "admin@corp.com"},
                    "serviceData": {
                        "policyDelta": {
                            "bindingDeltas": [
                                {"action": "REMOVE", "role": "roles/viewer", "member": "user:extra@corp.com"}
                            ]
                        }
                    },
                },
            }
        ]
        extra = _by_name(build_inventory(data), "extra@corp.com")
        self.assertIsNone(extra.created_at)
        self.assertIsNone(extra.created_by)

    def test_audit_activity_does_not_create_new_identity_rows(self):
        data = _snapshot()
        data["auditLogEntries"] = [
            {
                "timestamp": "2026-07-20T00:00:00Z",
                "protoPayload": {
                    "methodName": "storage.buckets.list",
                    "authenticationInfo": {"principalEmail": "drive-by@corp.com"},
                },
            }
        ]
        records = build_inventory(data)
        self.assertNotIn("drive-by@corp.com", {r.name for r in records})


class TestGcpClassificationReasons(unittest.TestCase):
    def test_user_binding_member_with_gserviceaccount_domain_is_machine(self):
        data = _snapshot()
        data["bindings"] = [{"role": "roles/viewer", "members": ["user:sa-misfiled@proj.iam.gserviceaccount.com"]}]
        record = _by_name(build_inventory(data), "sa-misfiled@proj.iam.gserviceaccount.com")
        self.assertEqual(record.classification, MACHINE)
        self.assertEqual(record.classification_reason, "workload email domain (gserviceaccount.com)")

    def test_reasons_present_on_all_gcp_records(self):
        records = build_inventory(_snapshot())
        self.assertTrue(all(r.classification_reason for r in records))
        by_type = {r.identity_type: r.classification_reason for r in records}
        self.assertEqual(by_type.get("service_account"), "service account")

    def test_workspace_user_reason(self):
        record = _by_name(build_inventory(_snapshot()), "dev@corp.com")
        self.assertEqual(record.classification, HUMAN)
        self.assertEqual(record.classification_reason, "Workspace directory user")

    def test_binding_member_reason(self):
        record = _by_name(build_inventory(_snapshot()), "extra@corp.com")
        self.assertEqual(record.classification, HUMAN)
        self.assertEqual(record.classification_reason, "user: IAM binding member")


if __name__ == "__main__":
    unittest.main()
