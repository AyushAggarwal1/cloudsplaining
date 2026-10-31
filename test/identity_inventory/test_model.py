import unittest
from datetime import datetime, timezone

from cloudsplaining.identity_inventory.model import HUMAN, MACHINE, IdentityRecord

REF = datetime(2026, 8, 1, tzinfo=timezone.utc)

EXPECTED_KEYS = [
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
]


class TestIdentityRecord(unittest.TestCase):
    def _record(self, **overrides):
        defaults = {
            "provider": "aws",
            "identity_type": "user",
            "id": "arn:aws:iam::111122223333:user/alice",
            "name": "alice",
            "classification": HUMAN,
            "created_at": datetime(2026, 7, 2, tzinfo=timezone.utc),
            "last_used": datetime(2026, 7, 31, 12, tzinfo=timezone.utc),
            "created_by": "arn:aws:iam::111122223333:user/admin",
        }
        defaults.update(overrides)
        return IdentityRecord(**defaults)

    def test_to_dict_has_exact_keys_in_order(self):
        self.assertEqual(list(self._record().to_dict(reference_time=REF).keys()), EXPECTED_KEYS)

    def test_derived_fields(self):
        row = self._record().to_dict(reference_time=REF)
        self.assertEqual(row["age_days"], 30)
        self.assertEqual(row["days_since_last_used"], 0)

    def test_timestamps_serialized_as_iso(self):
        row = self._record().to_dict(reference_time=REF)
        self.assertEqual(row["created_at"], "2026-07-02T00:00:00+00:00")
        self.assertEqual(row["last_used"], "2026-07-31T12:00:00+00:00")

    def test_unknown_created_at_gives_none_age(self):
        row = self._record(created_at=None).to_dict(reference_time=REF)
        self.assertIsNone(row["created_at"])
        self.assertIsNone(row["age_days"])

    def test_never_used_gives_none_days_since(self):
        row = self._record(last_used=None).to_dict(reference_time=REF)
        self.assertIsNone(row["last_used"])
        self.assertIsNone(row["days_since_last_used"])

    def test_default_reference_time_is_now(self):
        row = self._record().to_dict()
        self.assertGreaterEqual(row["age_days"], 30)

    def test_classification_constants(self):
        self.assertEqual(HUMAN, "human")
        self.assertEqual(MACHINE, "machine")


class TestClassificationReason(unittest.TestCase):
    def test_unknown_constant_exists(self):
        from cloudsplaining.identity_inventory.model import UNKNOWN

        self.assertEqual(UNKNOWN, "unknown")

    def test_classification_reason_defaults_to_none_and_serializes(self):
        record = IdentityRecord(provider="aws", identity_type="user", id="arn:x", name="x", classification=HUMAN)
        self.assertIsNone(record.classification_reason)
        self.assertIn("classification_reason", record.to_dict(reference_time=REF))

    def test_classification_reason_round_trips(self):
        record = IdentityRecord(
            provider="aws",
            identity_type="user",
            id="arn:x",
            name="x",
            classification="unknown",
            classification_reason="no credential evidence: credential report unavailable",
        )
        data = record.to_dict(reference_time=REF)
        self.assertEqual(data["classification"], "unknown")
        self.assertEqual(data["classification_reason"], "no credential evidence: credential report unavailable")


if __name__ == "__main__":
    unittest.main()
