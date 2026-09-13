"""Tests for how exclusion-match messages are emitted.

The "Excluded prefix/suffix" lines from ``is_name_excluded`` must be quiet for library
consumers (routed to ``logger.debug`` so they can be silenced via standard logging) but
must still print to stdout on the CLI. The CLI scopes that printing to the invocation and
restores the prior value afterward, so an in-process CLI run does not leak printing state
back into later library use.
"""

import contextlib
import io
import unittest

from click.testing import CliRunner

from cloudsplaining.bin.cli import cloudsplaining as cloudsplaining_cli
from cloudsplaining.scan.managed_policy_detail import ManagedPolicyDetails
from cloudsplaining.scan.role_details import RoleDetailList
from cloudsplaining.shared.exclusions import is_name_excluded, set_exclusion_output


class ExclusionOutputRoutingTestCase(unittest.TestCase):
    def setUp(self):
        # Every test starts from the library default and restores it afterward.
        self.addCleanup(set_exclusion_output, False)
        set_exclusion_output(False)

    def test_library_default_is_quiet_on_prefix_match(self):
        """As a library (default), a prefix exclusion match prints nothing to stdout."""
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            result = is_name_excluded("/aws-service-role/foo", "/aws-service-role*")
        self.assertTrue(result)
        self.assertEqual(buffer.getvalue(), "")

    def test_library_default_is_quiet_on_suffix_match(self):
        """As a library (default), a suffix exclusion match prints nothing to stdout."""
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            result = is_name_excluded("Secure-ish", "*ish")
        self.assertTrue(result)
        self.assertEqual(buffer.getvalue(), "")

    def test_prefix_match_is_logged_at_debug(self):
        """As a library, the prefix match is emitted as a DEBUG log record."""
        with self.assertLogs("cloudsplaining.shared.exclusions", level="DEBUG") as captured:
            is_name_excluded("/aws-service-role/foo", "/aws-service-role*")
        self.assertTrue(any("Excluded prefix" in message for message in captured.output))

    def test_cli_mode_prints_prefix_match(self):
        """When the CLI enables output, the prefix match still prints to stdout."""
        set_exclusion_output(True)
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            result = is_name_excluded("/aws-service-role/foo", "/aws-service-role*")
        self.assertTrue(result)
        self.assertIn("Excluded prefix", buffer.getvalue())

    def test_set_exclusion_output_returns_previous_value(self):
        """set_exclusion_output returns the prior value so callers can restore it."""
        self.assertFalse(set_exclusion_output(True))
        self.assertTrue(set_exclusion_output(False))

    def test_cli_invocation_does_not_leak_output_state(self):
        """Regression (Codex adversarial-review finding): after an in-process CLI run, the
        toggle is restored so a later library call stays quiet."""
        runner = CliRunner()
        with runner.isolated_filesystem():
            result = runner.invoke(cloudsplaining_cli, ["create-exclusions-file", "-o", "exclusions.yml"])
        self.assertEqual(result.exit_code, 0, msg=result.output)
        # The CLI must have restored the library-quiet default: a later library call that
        # hits an exclusion match prints nothing to stdout.
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            is_name_excluded("/aws-service-role/foo", "/aws-service-role*")
        self.assertEqual(buffer.getvalue(), "")


if __name__ == "__main__":
    unittest.main()


def _service_linked_role(name, service):
    return {
        "Path": f"/aws-service-role/{service}.amazonaws.com/",
        "RoleName": name,
        "RoleId": f"AROAEXAMPLE{name[-8:].upper()}",
        "Arn": f"arn:aws:iam::111122223333:role/aws-service-role/{service}.amazonaws.com/{name}",
        "CreateDate": "2023-01-02 11:24:31+00:00",
        "AssumeRolePolicyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": f"{service}.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        },
        "InstanceProfileList": [],
        "RolePolicyList": [],
        "AttachedManagedPolicies": [],
    }


class ServiceLinkedRoleSummaryTestCase(unittest.TestCase):
    """Building a RoleDetailList reports how many AWS service-linked roles were set aside, once, through the
    same routing as the per-match exclusion messages."""

    def setUp(self):
        self.addCleanup(set_exclusion_output, False)
        set_exclusion_output(False)

    @staticmethod
    def _build_role_detail_list():
        roles = [
            _service_linked_role("AWSServiceRoleForAmazonEKS", "eks"),
            _service_linked_role("AWSServiceRoleForSupport", "support"),
            {
                "Path": "/",
                "RoleName": "customer-role",
                "RoleId": "AROAEXAMPLECUSTOMER1",
                "Arn": "arn:aws:iam::111122223333:role/customer-role",
                "CreateDate": "2023-01-02 11:24:31+00:00",
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
                    ],
                },
                "InstanceProfileList": [],
                "RolePolicyList": [],
                "AttachedManagedPolicies": [],
            },
        ]
        return RoleDetailList(roles, ManagedPolicyDetails([]))

    def test_library_default_logs_summary_at_debug_and_stays_quiet(self):
        buffer = io.StringIO()
        with (
            self.assertLogs("cloudsplaining.shared.exclusions", level="DEBUG") as captured,
            contextlib.redirect_stdout(buffer),
        ):
            self._build_role_detail_list()
        self.assertEqual(buffer.getvalue(), "")
        self.assertTrue(any("2 AWS service-linked roles" in message for message in captured.output))

    def test_cli_mode_prints_summary_once(self):
        set_exclusion_output(True)
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            self._build_role_detail_list()
        output = buffer.getvalue()
        self.assertIn("2 AWS service-linked roles", output)
        self.assertEqual(output.count("AWS service-linked role"), 1)
