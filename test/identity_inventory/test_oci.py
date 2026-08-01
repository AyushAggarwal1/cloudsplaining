import unittest
from datetime import datetime, timezone

from cloudsplaining.identity_inventory.model import HUMAN, MACHINE
from cloudsplaining.identity_inventory.oci import build_inventory

USER_STATE_EXT = "urn:ietf:params:scim:schemas:oracle:idcs:extension:userState:User"


def _snapshot():
    return {
        "users": [
            {
                "id": "ocid1.user.oc1..ravi",
                "name": "ravi",
                "time-created": "2025-02-01T00:00:00.000Z",
                "last-successful-login-time": "2026-07-01T00:00:00.000Z",
                "capabilities": {"can-use-console-password": True, "can-use-api-keys": True},
            },
            {
                "id": "ocid1.user.oc1..reporting",
                "name": "reporting",
                "time-created": "2026-04-01T00:00:00.000Z",
                "capabilities": {"can-use-console-password": False, "can-use-api-keys": True},
            },
            {
                "id": "idcs-1",
                "userName": "maria@corp.com",
                "meta": {"created": "2026-01-01T00:00:00Z"},
                "idcsCreatedBy": {"display": "admin@corp.com", "value": "ocid1.user.oc1..admin"},
                USER_STATE_EXT: {"lastSuccessfulLoginDate": "2026-07-28T00:00:00Z"},
            },
        ],
        "dynamicGroups": [
            {"id": "ocid1.dynamicgroup.oc1..dg", "name": "instances-dg", "time-created": "2026-03-01T00:00:00Z"}
        ],
        "groups": [{"id": "ocid1.group.oc1..g", "name": "Admins"}],
    }


def _by_name(records, name):
    return next(r for r in records if r.name == name)


class TestOciInventory(unittest.TestCase):
    def test_users_and_dynamic_groups_inventoried_groups_skipped(self):
        records = build_inventory(_snapshot())
        self.assertEqual({r.name for r in records}, {"ravi", "reporting", "maria@corp.com", "instances-dg"})

    def test_console_user_is_human_with_kebab_case_fields(self):
        ravi = _by_name(build_inventory(_snapshot()), "ravi")
        self.assertEqual(ravi.classification, HUMAN)
        self.assertEqual(ravi.identity_type, "user")
        self.assertEqual(ravi.created_at, datetime(2025, 2, 1, tzinfo=timezone.utc))
        self.assertEqual(ravi.last_used, datetime(2026, 7, 1, tzinfo=timezone.utc))

    def test_api_keys_only_user_is_machine(self):
        self.assertEqual(_by_name(build_inventory(_snapshot()), "reporting").classification, MACHINE)

    def test_mfa_enrolled_user_is_human_despite_api_keys_only(self):
        data = _snapshot()
        data["users"].append(
            {
                "id": "ocid1.user.oc1..breakglass",
                "name": "breakglass",
                "isMfaActivated": True,
                "capabilities": {"can-use-console-password": False, "can-use-api-keys": True},
            }
        )
        self.assertEqual(_by_name(build_inventory(data), "breakglass").classification, HUMAN)

    def test_machine_name_wins_over_mfa(self):
        data = _snapshot()
        data["users"].append({"id": "ocid1.user.oc1..svc", "name": "svc-loader", "isMfaActivated": True})
        self.assertEqual(_by_name(build_inventory(data), "svc-loader").classification, MACHINE)

    def test_identity_domains_user_fields(self):
        maria = _by_name(build_inventory(_snapshot()), "maria@corp.com")
        self.assertEqual(maria.classification, HUMAN)
        self.assertEqual(maria.created_at, datetime(2026, 1, 1, tzinfo=timezone.utc))
        self.assertEqual(maria.created_by, "admin@corp.com")
        self.assertEqual(maria.last_used, datetime(2026, 7, 28, tzinfo=timezone.utc))

    def test_dynamic_group_is_machine(self):
        dg = _by_name(build_inventory(_snapshot()), "instances-dg")
        self.assertEqual(dg.classification, MACHINE)
        self.assertEqual(dg.identity_type, "dynamic_group")
        self.assertEqual(dg.created_at, datetime(2026, 3, 1, tzinfo=timezone.utc))
        self.assertIsNone(dg.last_used)

    def test_audit_events_fill_created_by(self):
        data = _snapshot()
        data["auditEvents"] = [
            {
                "eventType": "com.oraclecloud.identitycontrolplane.createuser",
                "data": {"resourceName": "ravi", "identity": {"principalName": "tenancy-admin"}},
            }
        ]
        self.assertEqual(_by_name(build_inventory(data), "ravi").created_by, "tenancy-admin")

    def test_idcs_created_by_wins_over_audit_events(self):
        data = _snapshot()
        data["auditEvents"] = [
            {
                "eventType": "com.oraclecloud.identitycontrolplane.createuser",
                "data": {"resourceName": "maria@corp.com", "identity": {"principalName": "someone-else"}},
            }
        ]
        self.assertEqual(_by_name(build_inventory(data), "maria@corp.com").created_by, "admin@corp.com")


if __name__ == "__main__":
    unittest.main()
