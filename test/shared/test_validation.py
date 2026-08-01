import unittest
from cloudsplaining.shared.validation import check_authorization_details_schema, check_exclusions_schema
import pytest
import os
import json


class FindExcessiveWildcardsTestCase(unittest.TestCase):
    def test_check_authorization_details_schema(self):
        """test_scanning.validate.check_authorization_details_schema"""
        example_authz_details_file = os.path.abspath(
            os.path.join(
                os.path.dirname(__file__),
                os.path.pardir,
                "files",
                "example-authz-details.json",
            )
        )
        with open(example_authz_details_file, "r") as json_file:
            cfg = json.load(json_file)
            decision = check_authorization_details_schema(cfg)
        self.assertTrue(decision)

    def test_authorization_details_schema_allows_inventory_enrichment_keys(self):
        """Enriched downloads carry credentialReport/cloudTrailEvents alongside the four AWS keys."""
        cfg = {
            "UserDetailList": [],
            "GroupDetailList": [],
            "RoleDetailList": [],
            "Policies": [],
            "credentialReport": "user,arn\nalice,arn:aws:iam::1:user/alice\n",
            "cloudTrailEvents": [],
        }
        self.assertTrue(check_authorization_details_schema(cfg))

    def test_exclusions_error(self):
        """shared.validation.check_exclusions_schema: Make sure an exception is raised if the format is incorrect"""
        exclusions_cfg = {
            "fake": ["MyRole"],
        }
        with self.assertRaises(Exception):
            check_exclusions_schema(exclusions_cfg)
