import unittest

from cloudsplaining.identity_inventory.classify import is_machine_name, machine_name_signal, resolve
from cloudsplaining.identity_inventory.model import HUMAN, MACHINE, UNKNOWN


class TestIsMachineName(unittest.TestCase):
    def test_machine_tokens_delimited(self):
        for name in (
            "svc-deployer",
            "backup_agent",
            "terraform-cloud",
            "jenkins",
            "ci",
            "cicd-runner",
            "github-actions-deploy",
            "etl.nightly",
            "lambda-invoker-2",
            "app-server",
            "argocd-updater",
            "flux-bootstrap",
            "prometheus",
            "kube-proxy-01",
        ):
            self.assertTrue(is_machine_name(name), name)

    def test_human_names(self):
        for name in ("alice", "bob.smith", "jane@contoso.com", "maria-garcia"):
            self.assertFalse(is_machine_name(name), name)

    def test_no_substring_false_positives(self):
        # "apparna" contains "app", "circleci-fan" is a person? no — but "apparna"
        # and "lucia" must not match on embedded tokens.
        for name in ("apparna", "lucia", "franci", "botswana-office"):
            self.assertFalse(is_machine_name(name), name)

    def test_email_local_part_is_considered(self):
        self.assertTrue(is_machine_name("svc-scanner@contoso.com"))

    def test_none_and_empty_are_human(self):
        self.assertFalse(is_machine_name(None))
        self.assertFalse(is_machine_name(""))


class TestResolve(unittest.TestCase):
    def test_first_present_signal_wins(self):
        self.assertEqual(
            resolve(None, (MACHINE, "automation-style name (token: svc)"), (HUMAN, "x"), fallback="f"),
            (MACHINE, "automation-style name (token: svc)"),
        )

    def test_no_signals_yields_unknown_with_fallback_reason(self):
        self.assertEqual(resolve(None, None, fallback="no evidence"), (UNKNOWN, "no evidence"))


class TestMachineNameSignal(unittest.TestCase):
    def test_new_tokens_match_whole_word(self):
        for name in (
            "ciem",
            "cspm-scanner",
            "acme-cnapp",
            "siem_forwarder",
            "devops.alerts@corp.com",
            "noreply@corp.com",
            "ses-smtp-user.20221228",
            "log-collector",
            "node-exporter-1",
            "data-ingest",
        ):
            self.assertIsNotNone(machine_name_signal(name), name)

    def test_token_reported_in_reason(self):
        self.assertEqual(machine_name_signal("ciem"), (MACHINE, "automation-style name (token: ciem)"))

    def test_tokens_do_not_match_inside_words(self):
        for name in ("lucia", "concierge", "smithy"):
            self.assertIsNone(machine_name_signal(name), name)

    def test_workload_email_domain(self):
        self.assertEqual(
            machine_name_signal("sa-123@my-project.iam.gserviceaccount.com"),
            (MACHINE, "workload email domain (gserviceaccount.com)"),
        )

    def test_none_and_empty_names_are_skipped(self):
        self.assertIsNone(machine_name_signal(None, ""))

    def test_first_matching_name_wins(self):
        self.assertEqual(
            machine_name_signal("Friendly Name", "svc-deployer"),
            (MACHINE, "automation-style name (token: svc)"),
        )


if __name__ == "__main__":
    unittest.main()
