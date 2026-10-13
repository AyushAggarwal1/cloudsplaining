import unittest
from unittest import mock

from click.testing import CliRunner

from cloudsplaining.command import collect_cloud


class TestCollectCloudCli(unittest.TestCase):
    def test_compartment_id_is_passed_to_the_oci_collector(self):
        collector = mock.Mock()
        collector.collect.return_value = {"account_id": "ocid.tenancy"}
        with mock.patch.object(collect_cloud, "get_collector", return_value=collector) as get:
            runner = CliRunner()
            with runner.isolated_filesystem():
                result = runner.invoke(
                    collect_cloud.collect_cloud,
                    ["-p", "oci", "--tenancy-id", "ocid.tenancy", "--compartment-id", "ocid.cmp.prod"],
                )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(get.call_args.kwargs["compartment_id"], "ocid.cmp.prod")
