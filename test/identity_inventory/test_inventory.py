import unittest
from datetime import datetime, timezone

from cloudsplaining.identity_inventory.inventory import (
    SUPPORTED_PROVIDERS,
    build_identity_inventory,
    build_identity_records,
    to_csv,
)
from cloudsplaining.identity_inventory.model import IdentityRecord

REF = datetime(2026, 8, 1, tzinfo=timezone.utc)

OCI_DATA = {"users": [{"id": "ocid1.user.oc1..x", "name": "ravi", "time-created": "2026-07-02T00:00:00Z"}]}
AWS_DATA = {
    "UserDetailList": [
        {"UserName": "alice", "Arn": "arn:aws:iam::1:user/alice", "CreateDate": "2026-07-02T00:00:00+00:00"}
    ]
}


class TestDispatcher(unittest.TestCase):
    def test_supported_providers(self):
        self.assertEqual(SUPPORTED_PROVIDERS, ("aws", "azure", "gcp", "oci"))

    def test_records_for_each_provider(self):
        for provider, data in (("aws", AWS_DATA), ("azure", {}), ("gcp", {}), ("oci", OCI_DATA)):
            records = build_identity_records(provider, data)
            self.assertIsInstance(records, list, provider)

    def test_oracle_aliases_to_oci(self):
        records = build_identity_records("oracle", OCI_DATA)
        self.assertEqual(records[0].provider, "oci")

    def test_provider_name_is_case_insensitive(self):
        self.assertEqual(build_identity_records("AWS", AWS_DATA)[0].provider, "aws")

    def test_unknown_provider_raises(self):
        with self.assertRaises(ValueError):
            build_identity_records("ibm", {})

    def test_inventory_returns_dicts_with_derived_fields(self):
        rows = build_identity_inventory("aws", AWS_DATA, reference_time=REF)
        self.assertEqual(rows[0]["name"], "alice")
        self.assertEqual(rows[0]["classification"], "human")
        self.assertEqual(rows[0]["age_days"], 30)


class TestCsv(unittest.TestCase):
    def test_to_csv_none_becomes_empty(self):
        record = IdentityRecord(
            provider="aws",
            identity_type="user",
            id="arn:aws:iam::1:user/alice",
            name="alice",
            classification="human",
            created_at=datetime(2026, 7, 2, tzinfo=timezone.utc),
        )
        text = to_csv([record.to_dict(reference_time=REF)])
        lines = text.strip().splitlines()
        self.assertEqual(
            lines[0],
            "provider,identity_type,id,name,classification,created_at,age_days,days_since_last_used,created_by,last_used",
        )
        self.assertIn("alice,human,2026-07-02T00:00:00+00:00,30,,,", lines[1])


if __name__ == "__main__":
    unittest.main()
