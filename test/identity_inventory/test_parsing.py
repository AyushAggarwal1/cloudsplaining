import unittest
from datetime import datetime, timezone

from cloudsplaining.identity_inventory.parsing import days_since, get_field, parse_timestamp

REF = datetime(2026, 8, 1, tzinfo=timezone.utc)


class TestParseTimestamp(unittest.TestCase):
    def test_iso_with_zulu_suffix(self):
        self.assertEqual(
            parse_timestamp("2024-01-15T10:30:00Z"),
            datetime(2024, 1, 15, 10, 30, tzinfo=timezone.utc),
        )

    def test_iso_with_utc_offset(self):
        self.assertEqual(
            parse_timestamp("2024-01-15T10:30:00+00:00"),
            datetime(2024, 1, 15, 10, 30, tzinfo=timezone.utc),
        )

    def test_iso_with_milliseconds(self):
        self.assertEqual(
            parse_timestamp("2025-02-01T00:00:00.000Z"),
            datetime(2025, 2, 1, tzinfo=timezone.utc),
        )

    def test_naive_iso_assumed_utc(self):
        self.assertEqual(
            parse_timestamp("2024-01-15T10:30:00"),
            datetime(2024, 1, 15, 10, 30, tzinfo=timezone.utc),
        )

    def test_date_only(self):
        self.assertEqual(parse_timestamp("2024-01-15"), datetime(2024, 1, 15, tzinfo=timezone.utc))

    def test_datetime_passthrough_naive_becomes_utc(self):
        aware = parse_timestamp(datetime(2024, 1, 15, 10, 30))
        self.assertEqual(aware, datetime(2024, 1, 15, 10, 30, tzinfo=timezone.utc))

    def test_credential_report_sentinels_are_none(self):
        for sentinel in ("N/A", "no_information", "not_supported", "", None):
            self.assertIsNone(parse_timestamp(sentinel))

    def test_garbage_is_none(self):
        self.assertIsNone(parse_timestamp("yesterday"))
        self.assertIsNone(parse_timestamp(12345))


class TestDaysSince(unittest.TestCase):
    def test_whole_days(self):
        self.assertEqual(days_since(datetime(2026, 7, 2, tzinfo=timezone.utc), REF), 30)

    def test_under_a_day_is_zero(self):
        self.assertEqual(days_since(datetime(2026, 7, 31, 12, tzinfo=timezone.utc), REF), 0)

    def test_none_is_none(self):
        self.assertIsNone(days_since(None, REF))

    def test_future_value_clamps_to_zero(self):
        self.assertEqual(days_since(datetime(2026, 8, 2, tzinfo=timezone.utc), REF), 0)


class TestGetField(unittest.TestCase):
    def test_camel_case(self):
        self.assertEqual(get_field({"timeCreated": "x"}, "timeCreated"), "x")

    def test_kebab_case(self):
        self.assertEqual(get_field({"time-created": "x"}, "timeCreated"), "x")

    def test_snake_case(self):
        self.assertEqual(get_field({"time_created": "x"}, "timeCreated"), "x")

    def test_missing_is_none(self):
        self.assertIsNone(get_field({}, "timeCreated"))

    def test_first_matching_name_wins(self):
        self.assertEqual(get_field({"name": "a", "userName": "b"}, "name", "userName"), "a")


if __name__ == "__main__":
    unittest.main()
