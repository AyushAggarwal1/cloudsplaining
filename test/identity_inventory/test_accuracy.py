import unittest
from datetime import datetime, timedelta, timezone
from typing import Any

from cloudsplaining.identity_inventory.aws import build_inventory as build_aws
from cloudsplaining.identity_inventory.azure import build_inventory as build_azure
from cloudsplaining.identity_inventory.gcp import build_inventory as build_gcp
from cloudsplaining.identity_inventory.model import HUMAN, MACHINE, UNKNOWN, IdentityRecord
from cloudsplaining.identity_inventory.oci import build_inventory as build_oci
from cloudsplaining.identity_inventory.parsing import parse_timestamp


def _by_id(records: list[IdentityRecord], record_id: str) -> IdentityRecord:
    return next(record for record in records if record.id == record_id)


class TestSharedTimestampAccuracy(unittest.TestCase):
    def test_timestamp_offsets_are_normalized_to_utc(self) -> None:
        parsed = parse_timestamp("2026-07-01T05:30:00+05:30")
        self.assertEqual(parsed, datetime(2026, 7, 1, tzinfo=timezone.utc))

    def test_naive_reference_time_and_offset_values_are_safe(self) -> None:
        record = IdentityRecord(
            provider="aws",
            identity_type="user",
            id="id",
            name="name",
            classification=HUMAN,
            created_at=datetime(2026, 7, 1, 5, 30, tzinfo=timezone(timedelta(hours=5, minutes=30))),
        )
        row = record.to_dict(reference_time=datetime(2026, 8, 1))
        self.assertEqual(row["created_at"], "2026-07-01T00:00:00+00:00")
        self.assertEqual(row["age_days"], 31)


class TestAwsAccuracy(unittest.TestCase):
    @staticmethod
    def _report_gap(created_at: str, generated_at: str | None) -> dict[str, Any]:
        data = {
            "UserDetailList": [
                {
                    "UserName": "alice",
                    "UserId": "AIDA1",
                    "Arn": "arn:aws:iam::111122223333:user/alice",
                    "CreateDate": created_at,
                }
            ],
            "RoleDetailList": [],
            "credentialReport": [{"user": "someone-else", "arn": "arn:aws:iam::111122223333:user/someone-else"}],
        }
        if generated_at is not None:
            data["credentialReportGeneratedTime"] = generated_at
        return data

    def test_preexisting_user_is_not_mislabeled_as_report_cache_race(self) -> None:
        record = build_aws(self._report_gap("2026-06-01T00:00:00Z", "2026-07-01T00:00:00Z"))[0]
        self.assertEqual(record.classification, UNKNOWN)
        self.assertEqual(record.classification_reason, "credential report row missing for pre-existing user")

    def test_actual_post_report_user_keeps_cache_race_reason(self) -> None:
        record = build_aws(self._report_gap("2026-07-02T00:00:00Z", "2026-07-01T00:00:00Z"))[0]
        self.assertEqual(record.classification_reason, "created after credential report was generated")

    def test_missing_generation_time_is_explicit(self) -> None:
        record = build_aws(self._report_gap("2026-07-02T00:00:00Z", None))[0]
        self.assertEqual(record.classification_reason, "credential report row missing; generation time unavailable")

    def test_identity_center_permission_set_role_is_human(self) -> None:
        records = build_aws(
            {
                "UserDetailList": [],
                "RoleDetailList": [
                    {
                        "RoleName": "AWSReservedSSO_AdministratorAccess_deadbeef",
                        "RoleId": "AROA1",
                        "Arn": (
                            "arn:aws:iam::111122223333:role/aws-reserved/sso.amazonaws.com/"
                            "AWSReservedSSO_AdministratorAccess_deadbeef"
                        ),
                        "Path": "/aws-reserved/sso.amazonaws.com/",
                    }
                ],
            }
        )
        self.assertEqual(records[0].classification, HUMAN)
        self.assertEqual(records[0].classification_reason, "IAM Identity Center role")

    def test_creator_event_is_correlated_with_current_create_date(self) -> None:
        data = self._report_gap("2026-07-02T00:00:00Z", None)
        data["cloudTrailEvents"] = [
            {
                "eventName": "CreateUser",
                "eventTime": "2026-06-01T00:00:00Z",
                "requestParameters": {"userName": "alice"},
                "userIdentity": {"arn": "arn:aws:iam::111122223333:user/old-admin"},
            },
            {
                "eventName": "CreateUser",
                "eventTime": "2026-07-02T00:01:00Z",
                "requestParameters": {"userName": "alice"},
                "userIdentity": {"arn": "arn:aws:iam::111122223333:user/current-admin"},
            },
        ]
        record = build_aws(data)[0]
        self.assertEqual(record.created_by, "arn:aws:iam::111122223333:user/current-admin")


class TestAzureAccuracy(unittest.TestCase):
    def test_role_assignment_only_principals_are_preserved(self) -> None:
        records = build_azure(
            {
                "users": [],
                "servicePrincipals": [],
                "roleAssignments": [
                    {"principalId": "user-only", "principalType": "User"},
                    {"principalId": "sp-only", "principalType": "ServicePrincipal"},
                    {"principalId": "group-only", "principalType": "Group"},
                    {"principalId": "sp-only", "principalType": "ServicePrincipal"},
                ],
            }
        )
        self.assertEqual({record.id for record in records}, {"user-only", "sp-only"})
        user = _by_id(records, "user-only")
        self.assertEqual(user.classification, UNKNOWN)
        self.assertEqual(user.classification_reason, "role-assignment user; Graph profile unavailable")
        sp = _by_id(records, "sp-only")
        self.assertEqual(sp.classification, MACHINE)

    def test_service_principal_last_use_is_order_independent(self) -> None:
        records = build_azure(
            {
                "users": [],
                "servicePrincipals": [{"id": "sp1", "appId": "app1", "displayName": "App"}],
                "servicePrincipalSignInActivities": [
                    {"appId": "app1", "lastSignInDateTime": "2026-07-20T00:00:00Z"},
                    {"appId": "app1", "lastSignInDateTime": "2026-06-20T00:00:00Z"},
                ],
            }
        )
        self.assertEqual(records[0].last_used, datetime(2026, 7, 20, tzinfo=timezone.utc))

    def test_creator_is_nearest_creation_audit_not_list_order(self) -> None:
        records = build_azure(
            {
                "users": [
                    {
                        "id": "u1",
                        "userPrincipalName": "pat@corp.com",
                        "createdDateTime": "2026-07-01T00:00:00Z",
                    }
                ],
                "servicePrincipals": [],
                "directoryAudits": [
                    {
                        "activityDisplayName": "Add user",
                        "activityDateTime": "2025-01-01T00:00:00Z",
                        "initiatedBy": {"user": {"userPrincipalName": "old-admin@corp.com"}},
                        "targetResources": [{"id": "u1"}],
                    },
                    {
                        "activityDisplayName": "Add user",
                        "activityDateTime": "2026-07-01T00:01:00Z",
                        "initiatedBy": {"user": {"userPrincipalName": "current-admin@corp.com"}},
                        "targetResources": [{"id": "u1"}],
                    },
                ],
            }
        )
        self.assertEqual(records[0].created_by, "current-admin@corp.com")


class TestGcpAccuracy(unittest.TestCase):
    def test_activity_before_retained_grant_prevents_false_creator(self) -> None:
        email = "person@corp.com"
        records = build_gcp(
            {
                "serviceAccounts": [],
                "bindings": [{"role": "roles/viewer", "members": [f"user:{email}"]}],
                "auditLogEntries": [
                    {
                        "timestamp": "2026-07-01T00:00:00Z",
                        "protoPayload": {
                            "methodName": "storage.buckets.list",
                            "authenticationInfo": {"principalEmail": email},
                        },
                    },
                    {
                        "timestamp": "2026-07-27T00:00:00Z",
                        "protoPayload": {
                            "methodName": "SetIamPolicy",
                            "authenticationInfo": {"principalEmail": "late-admin@corp.com"},
                            "serviceData": {
                                "policyDelta": {
                                    "bindingDeltas": [
                                        {"action": "ADD", "role": "roles/viewer", "member": f"user:{email}"}
                                    ]
                                }
                            },
                        },
                    },
                ],
            }
        )
        record = records[0]
        self.assertEqual(record.created_at, datetime(2026, 7, 1, tzinfo=timezone.utc))
        self.assertEqual(record.last_used, datetime(2026, 7, 1, tzinfo=timezone.utc))
        self.assertIsNone(record.created_by)

    def test_latest_service_account_creation_event_wins_regardless_of_order(self) -> None:
        email = "worker@proj.iam.gserviceaccount.com"
        records = build_gcp(
            {
                "serviceAccounts": [{"email": email, "uniqueId": "1"}],
                "bindings": [],
                "auditLogEntries": [
                    {
                        "timestamp": "2026-07-01T00:00:00Z",
                        "protoPayload": {
                            "methodName": "CreateServiceAccount",
                            "authenticationInfo": {"principalEmail": "current-admin@corp.com"},
                            "response": {"email": email},
                        },
                    },
                    {
                        "timestamp": "2025-01-01T00:00:00Z",
                        "protoPayload": {
                            "methodName": "CreateServiceAccount",
                            "authenticationInfo": {"principalEmail": "old-admin@corp.com"},
                            "response": {"email": email},
                        },
                    },
                ],
            }
        )
        self.assertEqual(records[0].created_at, datetime(2026, 7, 1, tzinfo=timezone.utc))
        self.assertEqual(records[0].created_by, "current-admin@corp.com")

    def test_latest_service_account_activity_wins_regardless_of_order(self) -> None:
        email = "worker@proj.iam.gserviceaccount.com"
        records = build_gcp(
            {
                "serviceAccounts": [{"email": email, "uniqueId": "1"}],
                "bindings": [],
                "serviceAccountActivities": [
                    {"activity": {"serviceAccount": {"email": email}, "lastAuthenticatedTime": "2026-07-20T00:00:00Z"}},
                    {"activity": {"serviceAccount": {"email": email}, "lastAuthenticatedTime": "2026-06-20T00:00:00Z"}},
                ],
            }
        )
        self.assertEqual(records[0].last_used, datetime(2026, 7, 20, tzinfo=timezone.utc))


class TestOciAccuracy(unittest.TestCase):
    def test_string_capability_booleans_are_not_misread(self) -> None:
        records = build_oci(
            {
                "users": [
                    {
                        "id": "ocid1.user.oc1..worker",
                        "name": "quiet-account",
                        "capabilities": {"canUseConsolePassword": "false", "canUseApiKeys": "true"},
                    }
                ]
            }
        )
        self.assertEqual(records[0].classification, MACHINE)
        self.assertEqual(records[0].classification_reason, "API-key-only capabilities")

    def test_creator_event_is_nearest_to_resource_creation(self) -> None:
        records = build_oci(
            {
                "users": [
                    {
                        "id": "ocid1.user.oc1..person",
                        "name": "person",
                        "timeCreated": "2026-07-01T00:00:00Z",
                    }
                ],
                "auditEvents": [
                    {
                        "eventType": "com.oraclecloud.identitycontrolplane.createuser",
                        "eventTime": "2025-01-01T00:00:00Z",
                        "data": {"resourceName": "person", "identity": {"principalName": "old-admin"}},
                    },
                    {
                        "eventType": "com.oraclecloud.identitycontrolplane.createuser",
                        "eventTime": "2026-07-01T00:01:00Z",
                        "data": {"resourceName": "person", "identity": {"principalName": "current-admin"}},
                    },
                ],
            }
        )
        self.assertEqual(records[0].created_by, "current-admin")


if __name__ == "__main__":
    unittest.main()
