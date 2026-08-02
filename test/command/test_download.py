import json
import tempfile
import unittest
from pathlib import Path

import boto3
from botocore.exceptions import ClientError
from click.testing import CliRunner
from moto import mock_aws

from cloudsplaining.command.download import (
    CLOUDTRAIL_CREATE_EVENT_NAMES,
    download,
    get_cloudtrail_create_events,
    get_credential_report,
    get_credential_supplement,
    users_missing_from_report,
)


class _DeniedIamClient:
    """Stand-in for an IAM client whose caller lacks iam:GenerateCredentialReport."""

    def generate_credential_report(self):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "nope"}}, "GenerateCredentialReport")


class _StubCloudTrailClient:
    """Stand-in for a CloudTrail client serving canned lookup_events pages."""

    def __init__(self, events_by_name=None, deny=False):
        self.events_by_name = events_by_name or {}
        self.deny = deny

    def get_paginator(self, operation):
        assert operation == "lookup_events"
        client = self

        class _Paginator:
            def paginate(self, LookupAttributes):  # noqa: N803 - boto3 casing
                if client.deny:
                    raise ClientError({"Error": {"Code": "AccessDenied", "Message": "nope"}}, "LookupEvents")
                event_name = LookupAttributes[0]["AttributeValue"]
                yield {"Events": client.events_by_name.get(event_name, [])}

        return _Paginator()


class TestGetCloudTrailCreateEvents(unittest.TestCase):
    def test_merges_create_user_and_create_role_events(self):
        stub = _StubCloudTrailClient(
            {
                "CreateUser": [{"CloudTrailEvent": '{"eventName": "CreateUser"}'}],
                "CreateRole": [{"CloudTrailEvent": '{"eventName": "CreateRole"}'}],
            }
        )
        events = get_cloudtrail_create_events(stub)
        self.assertEqual(len(events), 2)

    def test_access_denied_returns_none(self):
        self.assertIsNone(get_cloudtrail_create_events(_StubCloudTrailClient(deny=True)))


@mock_aws
class TestGetCredentialReport(unittest.TestCase):
    def test_returns_csv_text_and_generated_time(self):
        client = boto3.client("iam", region_name="us-east-1")
        client.create_user(UserName="alice")
        report = get_credential_report(client, delay_seconds=0)
        self.assertIsNotNone(report)
        text, generated_time = report
        self.assertIsInstance(text, str)
        self.assertTrue(text.startswith("user,arn"), text.splitlines()[0])
        # moto may omit GeneratedTime; live AWS always sets one.
        self.assertTrue(generated_time is None or isinstance(generated_time, str))

    def test_access_denied_returns_none(self):
        self.assertIsNone(get_credential_report(_DeniedIamClient(), delay_seconds=0))

    def test_event_names_include_credential_events(self):
        self.assertIn("CreateAccessKey", CLOUDTRAIL_CREATE_EVENT_NAMES)
        self.assertIn("CreateLoginProfile", CLOUDTRAIL_CREATE_EVENT_NAMES)


class _DeniedSupplementClient:
    """Stand-in for an IAM client denied on all per-user credential lookups."""

    def _deny(self, operation):
        raise ClientError({"Error": {"Code": "AccessDenied", "Message": "nope"}}, operation)

    def list_access_keys(self, UserName):  # noqa: N803 - boto3 casing
        self._deny("ListAccessKeys")

    def get_login_profile(self, UserName):  # noqa: N803 - boto3 casing
        self._deny("GetLoginProfile")

    def list_mfa_devices(self, UserName):  # noqa: N803 - boto3 casing
        self._deny("ListMFADevices")


@mock_aws
class TestCredentialSupplement(unittest.TestCase):
    def test_supplement_shapes_users(self):
        client = boto3.client("iam", region_name="us-east-1")
        client.create_user(UserName="machine-ish")
        client.create_access_key(UserName="machine-ish")
        client.create_user(UserName="human-ish")
        client.create_login_profile(UserName="human-ish", Password="Xx1234567890!aB")
        supplement = get_credential_supplement(client, ["machine-ish", "human-ish"])
        self.assertEqual(supplement["machine-ish"]["access_keys_active"], 1)
        self.assertFalse(supplement["machine-ish"]["has_login_profile"])
        self.assertTrue(supplement["human-ish"]["has_login_profile"])
        self.assertIn("checked_at", supplement["human-ish"])

    def test_missing_users_diff(self):
        users = [{"UserName": "a"}, {"UserName": "b"}]
        report = "user,arn\na,arn:aws:iam::111122223333:user/a\n"
        self.assertEqual(users_missing_from_report(users, report), ["b"])

    def test_denied_calls_omit_keys_but_do_not_raise(self):
        supplement = get_credential_supplement(_DeniedSupplementClient(), ["x"])
        self.assertEqual(list(supplement), ["x"])
        self.assertNotIn("access_keys_active", supplement["x"])
        self.assertNotIn("has_login_profile", supplement["x"])


@mock_aws
class TestDownloadEmbedsCredentialReport(unittest.TestCase):
    def setUp(self):
        boto3.client("iam", region_name="us-east-1").create_user(UserName="alice")

    def test_download_writes_credential_report_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = CliRunner().invoke(download, ["--output", tmp])
            self.assertEqual(result.exit_code, 0, result.output)
            saved = json.loads((Path(tmp) / "default.json").read_text())
            self.assertIn("credentialReport", saved)
            self.assertIn("user,arn", saved["credentialReport"])
            self.assertIn("UserDetailList", saved)

    def test_download_supplements_users_missing_from_report(self):
        # moto's credential report contains no rows, so every user is a gap user.
        with tempfile.TemporaryDirectory() as tmp:
            result = CliRunner().invoke(download, ["--output", tmp])
            self.assertEqual(result.exit_code, 0, result.output)
            saved = json.loads((Path(tmp) / "default.json").read_text())
            if "alice" not in saved["credentialReport"]:
                self.assertIn("alice", saved.get("credentialSupplement", {}))

    def test_skip_flags_omit_enrichment_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = CliRunner().invoke(
                download, ["--output", tmp, "--skip-credential-report", "--skip-cloudtrail-events"]
            )
            self.assertEqual(result.exit_code, 0, result.output)
            saved = json.loads((Path(tmp) / "default.json").read_text())
            self.assertNotIn("credentialReport", saved)
            self.assertNotIn("cloudTrailEvents", saved)


if __name__ == "__main__":
    unittest.main()
