import unittest

from cloudsplaining.multicloud import access_map
from cloudsplaining.multicloud.gcp.engine import GcpProvider
from cloudsplaining.multicloud.oci.engine import OciProvider
from cloudsplaining.multicloud.serialize import render


class TestAccessMap(unittest.TestCase):
    def test_gcp_rows_from_roles_collection(self):
        report = render(
            GcpProvider().scan(
                {
                    "customRoles": [{"name": "projects/p/roles/r", "includedPermissions": ["storage.objects.get"]}],
                    "bindings": [
                        {"role": "projects/p/roles/r", "members": ["user:a@b.com", "allUsers"]},
                    ],
                }
            )
        )
        rows = access_map.build(report)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["policyName"], "projects/p/roles/r")
        self.assertEqual(row["policyType"], "custom")
        self.assertIn("a@b.com", row["users"])
        self.assertIn("allUsers", row["public"])
        self.assertIn("storage.objects.get", row["actions"])

    def test_oci_rows_from_policies_collection(self):
        report = render(
            OciProvider().scan(
                {
                    "policies": [
                        {
                            "id": "p1",
                            "name": "AdminPolicy",
                            "compartmentId": "ocid1.tenancy.oc1..abc",
                            "statements": ["Allow group Admins to manage all-resources in tenancy"],
                        }
                    ]
                }
            )
        )
        rows = access_map.build(report)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["policyType"], "tenancy")
        self.assertIn("Admins", rows[0]["groups"])

    def test_only_attached_counts_public(self):
        report = render(GcpProvider().scan({"bindings": [{"role": "roles/viewer", "members": ["allUsers"]}]}))
        rows = access_map.build(report, only_attached=True)
        self.assertEqual(len(rows), 1)


if __name__ == "__main__":
    unittest.main()
