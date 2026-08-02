import json
import tempfile
import unittest
from pathlib import Path

from click.testing import CliRunner

from cloudsplaining.identity_inventory.__main__ import identity_inventory

AWS_DATA = {
    "UserDetailList": [
        {"UserName": "alice", "Arn": "arn:aws:iam::1:user/alice", "CreateDate": "2026-07-02T00:00:00+00:00"}
    ]
}


class TestCli(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.input_file = Path(self._tmp.name) / "aws.json"
        self.input_file.write_text(json.dumps(AWS_DATA))

    def _invoke(self, *args):
        return CliRunner().invoke(identity_inventory, args)

    def test_json_to_stdout(self):
        result = self._invoke("--provider", "aws", "--input", str(self.input_file))
        self.assertEqual(result.exit_code, 0, result.output)
        rows = json.loads(result.output)
        self.assertEqual(rows[0]["name"], "alice")
        # No credential report in AWS_DATA → honest unknown, not a silent human guess.
        self.assertEqual(rows[0]["classification"], "unknown")

    def test_reference_time_makes_age_deterministic(self):
        result = self._invoke(
            "--provider", "aws", "--input", str(self.input_file), "--reference-time", "2026-08-01T00:00:00Z"
        )
        rows = json.loads(result.output)
        self.assertEqual(rows[0]["age_days"], 30)

    def test_csv_to_file(self):
        out = Path(self._tmp.name) / "out.csv"
        result = self._invoke(
            "--provider", "aws", "--input", str(self.input_file), "--output", str(out), "--output-format", "csv"
        )
        self.assertEqual(result.exit_code, 0, result.output)
        content = out.read_text()
        self.assertTrue(
            content.startswith("provider,identity_type,id,name,classification,classification_reason,created_at")
        )
        self.assertIn("alice", content)

    def test_oracle_alias_accepted(self):
        oci_file = Path(self._tmp.name) / "oci.json"
        oci_file.write_text(json.dumps({"users": [{"id": "x", "name": "ravi"}]}))
        result = self._invoke("--provider", "oracle", "--input", str(oci_file))
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(json.loads(result.output)[0]["provider"], "oci")

    def test_unknown_provider_rejected(self):
        result = self._invoke("--provider", "ibm", "--input", str(self.input_file))
        self.assertNotEqual(result.exit_code, 0)


if __name__ == "__main__":
    unittest.main()
