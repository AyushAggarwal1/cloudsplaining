import unittest

from cloudsplaining.identity_inventory.classify import is_machine_name


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


if __name__ == "__main__":
    unittest.main()
