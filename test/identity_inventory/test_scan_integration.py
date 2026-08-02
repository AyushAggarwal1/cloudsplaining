"""The scan commands must embed the identity inventory in their JSON output."""

import json
import tempfile
import unittest
from pathlib import Path

from click.testing import CliRunner

from cloudsplaining.command.scan import scan_account_authorization_details
from cloudsplaining.command.scan_cloud import scan_cloud
from cloudsplaining.shared.exclusions import DEFAULT_EXCLUSIONS

AUTHZ_FIXTURE = Path(__file__).parent.parent / "files" / "example-authz-details.json"

INVENTORY_KEYS = {
    "provider",
    "identity_type",
    "id",
    "name",
    "classification",
    "classification_reason",
    "created_at",
    "age_days",
    "days_since_last_used",
    "created_by",
    "last_used",
}


class TestAwsScanEmbedsInventory(unittest.TestCase):
    def setUp(self):
        self.cfg = json.loads(AUTHZ_FIXTURE.read_text())

    def _scan(self, **kwargs):
        return scan_account_authorization_details(
            self.cfg, DEFAULT_EXCLUSIONS, account_name="acct", return_json_results=True, **kwargs
        )

    def test_results_and_findings_include_identity_inventory(self):
        output = self._scan()
        for key in ("iam_results", "iam_findings"):
            inventory = output[key].get("identity_inventory")
            self.assertIsInstance(inventory, list, key)
            self.assertTrue(inventory, key)

    def test_inventory_rows_are_fully_shaped(self):
        inventory = self._scan()["iam_results"]["identity_inventory"]
        names = {row["name"] for row in inventory}
        self.assertIn("obama", names)
        self.assertIn("MyRole", names)
        for row in inventory:
            self.assertEqual(set(row.keys()), INVENTORY_KEYS)
            self.assertEqual(row["provider"], "aws")
            self.assertIn(row["classification"], ("human", "machine", "unknown"))
            self.assertTrue(row["classification_reason"])

    def test_enriched_download_passes_schema_and_drives_classification(self):
        self.cfg["credentialReport"] = (
            "user,arn,password_enabled,mfa_active,access_key_1_active,access_key_1_last_rotated\n"
            "obama,arn:aws:iam::012345678901:user/obama,false,false,true,2026-05-01T00:00:00+00:00\n"
        )
        self.cfg["credentialReportGeneratedTime"] = "2026-08-02T10:00:00+00:00"
        self.cfg["credentialSupplement"] = {}
        self.cfg["cloudTrailEvents"] = []
        inventory = self._scan()["iam_results"]["identity_inventory"]
        by_name = {row["name"]: row for row in inventory}
        self.assertEqual(by_name["obama"]["classification"], "machine")
        key_row = by_name["obama/access-key-1"]
        self.assertEqual(key_row["identity_type"], "access_key")
        self.assertEqual(key_row["created_by"], "arn:aws:iam::012345678901:user/obama")

    def test_written_results_file_includes_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            self._scan(output_directory=tmp, write_data_files=True)
            written = json.loads((Path(tmp) / "iam-results-acct.json").read_text())
            self.assertIn("identity_inventory", written)
            self.assertTrue(written["identity_inventory"])


class TestScanCloudEmbedsInventory(unittest.TestCase):
    def _invoke_json(self, provider, payload):
        with tempfile.TemporaryDirectory() as tmp:
            input_file = Path(tmp) / "snapshot.json"
            input_file.write_text(payload)
            return CliRunner().invoke(scan_cloud, ["-p", provider, "-i", str(input_file), "-o", "json"])

    def test_azure_scan_json_includes_inventory(self):
        snapshot = {
            "users": [{"id": "u1", "userPrincipalName": "jane@contoso.com", "createdDateTime": "2025-08-01T00:00:00Z"}],
            "servicePrincipals": [
                {"id": "sp1", "appId": "a1", "displayName": "deploy-pipeline", "servicePrincipalType": "Application"}
            ],
        }
        result = self._invoke_json("azure", json.dumps(snapshot))
        self.assertEqual(result.exit_code, 0, result.output)
        inventory = json.loads(result.output)["identity_inventory"]
        by_name = {row["name"]: row for row in inventory}
        self.assertEqual(by_name["jane@contoso.com"]["classification"], "human")
        self.assertEqual(by_name["deploy-pipeline"]["classification"], "machine")

    def test_oci_scan_json_includes_inventory(self):
        snapshot = {"users": [{"id": "ocid1.user.oc1..x", "name": "ravi", "time-created": "2026-01-01T00:00:00Z"}]}
        result = self._invoke_json("oci", json.dumps(snapshot))
        self.assertEqual(result.exit_code, 0, result.output)
        inventory = json.loads(result.output)["identity_inventory"]
        self.assertEqual(inventory[0]["name"], "ravi")
        self.assertEqual(inventory[0]["provider"], "oci")

    def test_oci_statement_list_input_has_no_inventory(self):
        result = self._invoke_json("oci", "Allow any-user to manage buckets in tenancy\n")
        report = json.loads(result.output)
        self.assertNotIn("identity_inventory", report)


if __name__ == "__main__":
    unittest.main()
