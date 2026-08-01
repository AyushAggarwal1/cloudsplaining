import json
import tempfile
import unittest
from pathlib import Path

import boto3
from botocore.exceptions import ClientError
from click.testing import CliRunner
from moto import mock_aws

from cloudsplaining.command.download import download, get_cloudtrail_create_events, get_credential_report


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
    def test_returns_csv_text(self):
        client = boto3.client("iam", region_name="us-east-1")
        client.create_user(UserName="alice")
        report = get_credential_report(client, delay_seconds=0)
        self.assertIsInstance(report, str)
        self.assertTrue(report.startswith("user,arn"), report.splitlines()[0])

    def test_access_denied_returns_none(self):
        self.assertIsNone(get_credential_report(_DeniedIamClient(), delay_seconds=0))


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
