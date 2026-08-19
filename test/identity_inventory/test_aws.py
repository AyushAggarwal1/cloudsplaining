import json
import unittest
from datetime import datetime, timezone

from cloudsplaining.identity_inventory.aws import build_inventory
from cloudsplaining.identity_inventory.model import HUMAN, MACHINE, UNKNOWN

REF = datetime(2026, 8, 1, tzinfo=timezone.utc)

SAML_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Federated": "arn:aws:iam::111122223333:saml-provider/okta"},
            "Action": "sts:AssumeRoleWithSAML",
        }
    ],
}

EC2_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
}


def _authz_details():
    return {
        "UserDetailList": [
            {
                "UserName": "alice",
                "UserId": "AIDAALICE",
                "Arn": "arn:aws:iam::111122223333:user/alice",
                "Path": "/",
                "CreateDate": "2026-07-02T00:00:00+00:00",
            },
            {
                "UserName": "svc-terraform",
                "UserId": "AIDASVC",
                "Arn": "arn:aws:iam::111122223333:user/svc-terraform",
                "Path": "/",
                "CreateDate": "2025-01-01T00:00:00+00:00",
            },
        ],
        "GroupDetailList": [],
        "RoleDetailList": [
            {
                "RoleName": "app-server-role",
                "RoleId": "AROAAPP",
                "Arn": "arn:aws:iam::111122223333:role/app-server-role",
                "Path": "/",
                "CreateDate": "2026-05-01T00:00:00+00:00",
                "AssumeRolePolicyDocument": EC2_TRUST,
                "RoleLastUsed": {"LastUsedDate": "2026-07-22T00:00:00+00:00", "Region": "us-east-1"},
            },
            {
                "RoleName": "sso-developer",
                "RoleId": "AROASSO",
                "Arn": "arn:aws:iam::111122223333:role/sso-developer",
                "Path": "/",
                "CreateDate": "2026-01-01T00:00:00+00:00",
                "AssumeRolePolicyDocument": SAML_TRUST,
                "RoleLastUsed": {},
            },
            {
                "RoleName": "AWSServiceRoleForSupport",
                "RoleId": "AROASLR",
                "Arn": "arn:aws:iam::111122223333:role/aws-service-role/support.amazonaws.com/AWSServiceRoleForSupport",
                "Path": "/aws-service-role/support.amazonaws.com/",
                "CreateDate": "2024-01-01T00:00:00+00:00",
                "AssumeRolePolicyDocument": {"Statement": []},
            },
        ],
        "Policies": [],
    }


def _by_name(records, name):
    return next(r for r in records if r.name == name)


class TestAwsInventory(unittest.TestCase):
    def test_every_user_and_role_is_inventoried(self):
        records = build_inventory(_authz_details())
        self.assertEqual(
            {r.name for r in records},
            {
                "alice",
                "svc-terraform",
                "app-server-role",
                "sso-developer",
                "AWSServiceRoleForSupport",
            },
        )

    def test_user_without_credential_data_is_unknown(self):
        alice = _by_name(build_inventory(_authz_details()), "alice")
        self.assertEqual(alice.classification, UNKNOWN)
        self.assertEqual(alice.classification_reason, "no credential evidence: credential report unavailable")
        self.assertEqual(alice.provider, "aws")
        self.assertEqual(alice.identity_type, "user")
        self.assertEqual(alice.id, "arn:aws:iam::111122223333:user/alice")
        self.assertEqual(alice.created_at, datetime(2026, 7, 2, tzinfo=timezone.utc))

    def test_machine_named_user_is_machine(self):
        self.assertEqual(_by_name(build_inventory(_authz_details()), "svc-terraform").classification, MACHINE)

    def test_role_defaults_to_machine_with_role_last_used(self):
        role = _by_name(build_inventory(_authz_details()), "app-server-role")
        self.assertEqual(role.classification, MACHINE)
        self.assertEqual(role.identity_type, "role")
        self.assertEqual(role.last_used, datetime(2026, 7, 22, tzinfo=timezone.utc))

    def test_saml_federated_role_is_human(self):
        self.assertEqual(_by_name(build_inventory(_authz_details()), "sso-developer").classification, HUMAN)

    def test_service_linked_role_is_machine(self):
        role = _by_name(build_inventory(_authz_details()), "AWSServiceRoleForSupport")
        self.assertEqual(role.classification, MACHINE)

    def test_credential_report_rows_fill_user_last_used(self):
        data = _authz_details()
        data["credentialReport"] = [
            {
                "user": "alice",
                "arn": "arn:aws:iam::111122223333:user/alice",
                "password_last_used": "2026-07-25T00:00:00+00:00",
                "access_key_1_last_used_date": "2026-07-31T00:00:00+00:00",
                "access_key_2_last_used_date": "N/A",
            }
        ]
        alice = _by_name(build_inventory(data), "alice")
        self.assertEqual(alice.last_used, datetime(2026, 7, 31, tzinfo=timezone.utc))

    def test_credential_report_as_csv_string(self):
        data = _authz_details()
        data["credentialReport"] = (
            "user,arn,password_last_used,access_key_1_last_used_date,access_key_2_last_used_date\n"
            "alice,arn:aws:iam::111122223333:user/alice,2026-07-25T00:00:00+00:00,no_information,N/A\n"
        )
        alice = _by_name(build_inventory(data), "alice")
        self.assertEqual(alice.last_used, datetime(2026, 7, 25, tzinfo=timezone.utc))

    def test_cloudtrail_events_fill_created_by(self):
        data = _authz_details()
        data["cloudTrailEvents"] = [
            {
                "eventName": "CreateUser",
                "requestParameters": {"userName": "alice"},
                "userIdentity": {"arn": "arn:aws:iam::111122223333:user/admin-joe"},
            },
            {
                "CloudTrailEvent": json.dumps(
                    {
                        "eventName": "CreateRole",
                        "requestParameters": {"roleName": "app-server-role"},
                        "userIdentity": {"arn": "arn:aws:iam::111122223333:user/svc-terraform"},
                    }
                )
            },
        ]
        records = build_inventory(data)
        self.assertEqual(_by_name(records, "alice").created_by, "arn:aws:iam::111122223333:user/admin-joe")
        self.assertEqual(
            _by_name(records, "app-server-role").created_by, "arn:aws:iam::111122223333:user/svc-terraform"
        )

    def test_service_linked_role_creation_event_fills_created_by(self):
        # CreateServiceLinkedRole carries the service name in requestParameters;
        # the created role's name only appears in the response.
        data = _authz_details()
        data["cloudTrailEvents"] = [
            {
                "eventName": "CreateServiceLinkedRole",
                "requestParameters": {"awsServiceName": "support.amazonaws.com"},
                "responseElements": {"role": {"roleName": "AWSServiceRoleForSupport"}},
                "userIdentity": {"arn": "arn:aws:iam::111122223333:user/admin-joe"},
            }
        ]
        role = _by_name(build_inventory(data), "AWSServiceRoleForSupport")
        self.assertEqual(role.created_by, "arn:aws:iam::111122223333:user/admin-joe")

    def test_created_by_unknown_without_events(self):
        self.assertIsNone(_by_name(build_inventory(_authz_details()), "alice").created_by)

    def test_derived_fields_via_to_dict(self):
        alice = _by_name(build_inventory(_authz_details()), "alice").to_dict(reference_time=REF)
        self.assertEqual(alice["age_days"], 30)
        self.assertIsNone(alice["days_since_last_used"])


class TestAwsCredentialShapeClassification(unittest.TestCase):
    """Credential-shape signals (NHInsight-style): console password / MFA / access keys."""

    def _inventory_with_report(self, row):
        data = _authz_details()
        row.setdefault("user", "alice")
        row.setdefault("arn", "arn:aws:iam::111122223333:user/alice")
        data["credentialReport"] = [row]
        return build_inventory(data)

    def test_keys_only_user_is_machine(self):
        records = self._inventory_with_report(
            {"password_enabled": "false", "mfa_active": "false", "access_key_1_active": "true"}
        )
        self.assertEqual(_by_name(records, "alice").classification, MACHINE)

    def test_console_password_user_is_human(self):
        records = self._inventory_with_report(
            {"password_enabled": "true", "mfa_active": "false", "access_key_1_active": "true"}
        )
        self.assertEqual(_by_name(records, "alice").classification, HUMAN)

    def test_mfa_user_is_human(self):
        records = self._inventory_with_report(
            {"password_enabled": "false", "mfa_active": "true", "access_key_1_active": "true"}
        )
        self.assertEqual(_by_name(records, "alice").classification, HUMAN)

    def test_zero_credential_row_is_unknown(self):
        records = self._inventory_with_report(
            {"password_enabled": "false", "mfa_active": "false", "access_key_1_active": "false"}
        )
        alice = _by_name(records, "alice")
        self.assertEqual(alice.classification, UNKNOWN)
        self.assertEqual(alice.classification_reason, "no credentials provisioned (credential report)")

    def test_boolean_values_from_parsed_rows_work(self):
        records = self._inventory_with_report(
            {"password_enabled": False, "mfa_active": False, "access_key_2_active": True}
        )
        self.assertEqual(_by_name(records, "alice").classification, MACHINE)

    def test_machine_name_wins_over_console_access(self):
        data = _authz_details()
        data["credentialReport"] = [{"user": "svc-terraform", "password_enabled": "true", "mfa_active": "true"}]
        self.assertEqual(_by_name(build_inventory(data), "svc-terraform").classification, MACHINE)


_REPORT_HEADER = (
    "user,arn,password_enabled,mfa_active,access_key_1_active,access_key_1_last_rotated,"
    "access_key_2_active,access_key_2_last_rotated,password_last_used,"
    "access_key_1_last_used_date,access_key_2_last_used_date\n"
)


class TestClassificationReasons(unittest.TestCase):
    def _records(self, data):
        return {record.name: record for record in build_inventory(data)}

    def test_user_missing_from_present_report_is_unknown_with_race_reason(self):
        data = _authz_details()
        data["credentialReport"] = (
            _REPORT_HEADER
            + "someoneelse,arn:aws:iam::111122223333:user/someoneelse,true,false,false,N/A,false,N/A,N/A,N/A,N/A\n"
        )
        neutral = self._records(data)["alice"]
        self.assertEqual(neutral.classification, UNKNOWN)
        self.assertEqual(neutral.classification_reason, "created after credential report was generated")

    def test_password_user_is_human_with_report_reason(self):
        data = _authz_details()
        data["credentialReport"] = (
            _REPORT_HEADER + "alice,arn:aws:iam::111122223333:user/alice,true,false,false,N/A,false,N/A,N/A,N/A,N/A\n"
        )
        alice = self._records(data)["alice"]
        self.assertEqual(alice.classification, HUMAN)
        self.assertEqual(alice.classification_reason, "console password or MFA (credential report)")

    def test_keys_only_user_is_machine_with_report_reason(self):
        data = _authz_details()
        data["credentialReport"] = (
            _REPORT_HEADER
            + "alice,arn:aws:iam::111122223333:user/alice,false,false,true,2026-01-01T00:00:00+00:00,false,N/A,N/A,N/A,N/A\n"
        )
        alice = self._records(data)["alice"]
        self.assertEqual(alice.classification, MACHINE)
        self.assertEqual(alice.classification_reason, "active access keys, no console password (credential report)")

    def test_machine_named_user_reason(self):
        record = self._records(_authz_details())["svc-terraform"]
        self.assertEqual(record.classification, MACHINE)
        self.assertEqual(record.classification_reason, "automation-style name (token: svc)")

    def test_role_and_access_key_reasons(self):
        data = _authz_details()
        data["credentialReport"] = (
            _REPORT_HEADER
            + "alice,arn:aws:iam::111122223333:user/alice,false,false,true,2026-01-01T00:00:00+00:00,false,N/A,N/A,N/A,N/A\n"
        )
        records = self._records(data)
        reasons = {record.classification_reason for record in records.values()}
        self.assertIn("access key", reasons)  # alice/access-key-1 child record
        self.assertIn("SAML-federated role", reasons)  # sso-developer
        self.assertIn("workload role", reasons)  # app-server-role
        self.assertIn("AWS service role", reasons)  # AWSServiceRoleForSupport


def _create_event(event_name, user_name):
    return {
        "CloudTrailEvent": json.dumps(
            {
                "eventName": event_name,
                "userIdentity": {"arn": "arn:aws:iam::111122223333:user/creator"},
                "requestParameters": {"userName": user_name},
            }
        )
    }


class TestGapUserEvidence(unittest.TestCase):
    """The ciem scenario: user created after the cached credential report was generated."""

    def _records(self, data):
        return {record.name: record for record in build_inventory(data)}

    def _gap_data(self):
        data = _authz_details()
        data["credentialReport"] = (
            _REPORT_HEADER
            + "someoneelse,arn:aws:iam::111122223333:user/someoneelse,true,false,false,N/A,false,N/A,N/A,N/A,N/A\n"
        )
        return data

    def test_gap_user_with_access_key_event_is_machine(self):
        data = self._gap_data()
        data["cloudTrailEvents"] = [_create_event("CreateAccessKey", "alice")]
        alice = self._records(data)["alice"]
        self.assertEqual(alice.classification, MACHINE)
        self.assertEqual(alice.classification_reason, "access key created, no console password (CloudTrail events)")

    def test_gap_user_with_login_profile_event_is_human_even_with_key_event(self):
        data = self._gap_data()
        data["cloudTrailEvents"] = [
            _create_event("CreateAccessKey", "alice"),
            _create_event("CreateLoginProfile", "alice"),
        ]
        alice = self._records(data)["alice"]
        self.assertEqual(alice.classification, HUMAN)
        self.assertEqual(alice.classification_reason, "console login profile created (CloudTrail events)")

    def test_supplement_beats_events_and_stale_report(self):
        data = self._gap_data()
        data["cloudTrailEvents"] = [_create_event("CreateAccessKey", "alice")]
        data["credentialSupplement"] = {
            "alice": {
                "access_keys_active": 0,
                "has_login_profile": True,
                "mfa_devices": 0,
                "checked_at": "2026-08-02T15:00:00+00:00",
            }
        }
        alice = self._records(data)["alice"]
        self.assertEqual(alice.classification, HUMAN)
        self.assertEqual(alice.classification_reason, "console password or MFA (live IAM lookup)")

    def test_supplement_keys_only_is_machine(self):
        data = self._gap_data()
        data["credentialSupplement"] = {
            "alice": {"access_keys_active": 2, "has_login_profile": False, "mfa_devices": 0}
        }
        alice = self._records(data)["alice"]
        self.assertEqual(alice.classification, MACHINE)
        self.assertEqual(alice.classification_reason, "active access keys, no console password (live IAM lookup)")

    def test_partial_supplement_row_is_ignored(self):
        data = self._gap_data()
        data["credentialSupplement"] = {"alice": {"mfa_devices": 0}}  # both required keys absent
        alice = self._records(data)["alice"]
        self.assertEqual(alice.classification, UNKNOWN)
        self.assertEqual(alice.classification_reason, "created after credential report was generated")

    def test_gap_user_with_no_evidence_is_unknown(self):
        alice = self._records(self._gap_data())["alice"]
        self.assertEqual(alice.classification, UNKNOWN)
        self.assertEqual(alice.classification_reason, "created after credential report was generated")


class TestAwsAccessKeyChildRows(unittest.TestCase):
    """Access keys become child identities with structural parent attribution (never expires)."""

    def _inventory(self, row_extra):
        data = _authz_details()
        row = {"user": "alice", "arn": "arn:aws:iam::111122223333:user/alice"}
        row.update(row_extra)
        data["credentialReport"] = [row]
        return build_inventory(data)

    def test_active_key_becomes_child_identity(self):
        records = self._inventory(
            {
                "access_key_1_active": "true",
                "access_key_1_last_rotated": "2026-05-01T00:00:00+00:00",
                "access_key_1_last_used_date": "2026-07-30T00:00:00+00:00",
            }
        )
        key = _by_name(records, "alice/access-key-1")
        self.assertEqual(key.identity_type, "access_key")
        self.assertEqual(key.classification, MACHINE)
        self.assertEqual(key.id, "arn:aws:iam::111122223333:user/alice/access-key-1")
        self.assertEqual(key.created_at, datetime(2026, 5, 1, tzinfo=timezone.utc))
        self.assertEqual(key.last_used, datetime(2026, 7, 30, tzinfo=timezone.utc))
        self.assertEqual(key.created_by, "arn:aws:iam::111122223333:user/alice")

    def test_absent_key_slots_produce_no_rows(self):
        records = self._inventory(
            {
                "access_key_1_active": "false",
                "access_key_1_last_rotated": "N/A",
                "access_key_2_active": "false",
                "access_key_2_last_rotated": "N/A",
            }
        )
        self.assertEqual([r.name for r in records if r.identity_type == "access_key"], [])

    def test_inactive_but_existing_key_is_still_inventoried(self):
        records = self._inventory(
            {"access_key_2_active": "false", "access_key_2_last_rotated": "2024-01-01T00:00:00+00:00"}
        )
        key = _by_name(records, "alice/access-key-2")
        self.assertEqual(key.created_at, datetime(2024, 1, 1, tzinfo=timezone.utc))
        self.assertIsNone(key.last_used)

    def test_no_credential_report_means_no_key_rows(self):
        records = build_inventory(_authz_details())
        self.assertEqual([r for r in records if r.identity_type == "access_key"], [])


if __name__ == "__main__":
    unittest.main()
