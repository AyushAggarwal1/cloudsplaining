"""Exclusions.keep_excluded: excluded policies stay in the results, flagged and findings-free.

The default exclusions ship AdministratorAccess (upstream skips analyzing it purely for
speed), so with the drop behavior an account's admins appear to hold no permissions in
the results JSON consumed by downstream tooling. keep_excluded keeps such policies in
the output - attached, document included, marked is_excluded - while still skipping
their expensive analysis so they produce no findings.
"""

import json
import os
import unittest

from cloudsplaining.scan.authorization_details import AuthorizationDetails
from cloudsplaining.scan.inline_policy import InlinePolicy
from cloudsplaining.shared.constants import DEFAULT_EXCLUSIONS_CONFIG
from cloudsplaining.shared.exclusions import DEFAULT_EXCLUSIONS, Exclusions

example_authz_details_file = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        os.path.pardir,
        "files",
        "example-authz-details.json",
    )
)
with open(example_authz_details_file) as f:
    auth_details_json = json.loads(f.read())

ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
CATEGORIES = (
    "PrivilegeEscalation",
    "DataExfiltration",
    "ResourceExposure",
    "ServiceWildcard",
    "CredentialsExposure",
    "InfrastructureModification",
)


def _policy_by_name(collection, name):
    for policy in collection.values():
        if policy.get("PolicyName") == name:
            return policy
    return None


def _user_by_name(users, name):
    for user in users.values():
        if user.get("name") == name:
            return user
    return None


class TestKeepExcludedFlag(unittest.TestCase):
    def test_exclusions_default_to_dropping(self):
        self.assertFalse(DEFAULT_EXCLUSIONS.keep_excluded)
        self.assertFalse(Exclusions(DEFAULT_EXCLUSIONS_CONFIG).keep_excluded)
        self.assertTrue(Exclusions(DEFAULT_EXCLUSIONS_CONFIG, keep_excluded=True).keep_excluded)

    def test_default_behavior_still_drops_excluded_policies(self):
        authorization_details = AuthorizationDetails(auth_details_json, DEFAULT_EXCLUSIONS)
        results = authorization_details.results
        self.assertIsNone(_policy_by_name(results["aws_managed_policies"], "AdministratorAccess"))
        obama = _user_by_name(results["users"], "obama")
        self.assertEqual(obama["aws_managed_policies"], {})


class TestKeepExcludedResults(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.exclusions = Exclusions(DEFAULT_EXCLUSIONS_CONFIG, keep_excluded=True)
        cls.authorization_details = AuthorizationDetails(auth_details_json, cls.exclusions)
        cls.results = cls.authorization_details.results

    def test_excluded_policy_present_flagged_and_findings_free(self):
        entry = _policy_by_name(self.results["aws_managed_policies"], "AdministratorAccess")
        self.assertIsNotNone(entry)
        self.assertTrue(entry["is_excluded"])
        for category in CATEGORIES:
            self.assertEqual(entry[category]["findings"], [])
        self.assertTrue(entry["PolicyVersionList"])  # the document rides along

    def test_excluded_policy_attachments_preserved(self):
        entry = _policy_by_name(self.results["aws_managed_policies"], "AdministratorAccess")
        self.assertIn("admin", entry["AttachedTo"]["groups"])
        self.assertIn("obama", entry["AttachedTo"]["users"])
        obama = _user_by_name(self.results["users"], "obama")
        self.assertIn("AdministratorAccess", obama["aws_managed_policies"].values())

    def test_excluded_policy_is_not_analyzed(self):
        policy = self.authorization_details.policies.get_policy_detail(ADMIN_ARN)
        self.assertTrue(policy.is_excluded)
        self.assertIsNone(policy._policy_document)

    def test_non_excluded_policies_still_analyzed(self):
        findings = 0
        for collection in ("aws_managed_policies", "customer_managed_policies", "inline_policies"):
            for entry in self.results[collection].values():
                if entry.get("is_excluded"):
                    continue
                findings += sum(len(entry[category]["findings"]) for category in CATEGORIES if category in entry)
        self.assertGreater(findings, 0)


class TestKeepExcludedInlinePolicy(unittest.TestCase):
    def test_excluded_inline_policy_kept_without_findings(self):
        config = {**DEFAULT_EXCLUSIONS_CONFIG, "policies": ["bad-inline*"]}
        exclusions = Exclusions(config, keep_excluded=True)
        detail = {
            "PolicyName": "bad-inline-policy",
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}],
            },
        }
        inline_policy = InlinePolicy(detail, exclusions=exclusions)
        self.assertTrue(inline_policy.is_excluded)
        output = inline_policy.json
        self.assertTrue(output["is_excluded"])
        for category in CATEGORIES:
            if category in output:
                self.assertEqual(output[category]["findings"], [])
