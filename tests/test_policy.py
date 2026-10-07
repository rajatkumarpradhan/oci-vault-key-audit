import contextlib
import io
import json
import os
import tempfile
import unittest
from datetime import date

from vault_audit import analysis, model
from vault_audit.cli import main
from vault_audit.policy import Policy

EX = os.path.join(os.path.dirname(__file__), "..", "examples", "synthetic.json")
POL = os.path.join(os.path.dirname(__file__), "..", "examples", "policy.json")


def inv(*keys, as_of="2026-10-01"):
    return model.load({"as_of": as_of, "keys": list(keys)})


def aes(name, vault, rotated, **kw):
    d = {"name": name, "vault": vault, "algorithm": "AES", "protection": "HSM", "state": "ENABLED",
         "created": "2024-01-01", "last_rotated": rotated, "auto_rotation_days": 30}
    d.update(kw)
    return d


def rules(fs):
    return sorted((f.key, f.rule) for f in fs)


class PolicyTests(unittest.TestCase):
    # 2026-10-01 minus 2026-05-01 = 153 days; minus 2026-03-01 = 214 days
    def test_no_policy_uses_global_limit(self):
        self.assertEqual(analysis.analyze(inv(aes("k", "prod-vault", "2026-03-01"))), [])

    def test_vault_limit_tightens(self):
        p = Policy.from_doc({"vaults": {"prod-vault": {"max_age_days": 180}}})
        fs = analysis.analyze(inv(aes("k", "prod-vault", "2026-03-01"), aes("k", "dev-vault", "2026-03-01")), policy=p)
        self.assertEqual([(f.vault, f.rule) for f in fs], [("prod-vault", "KM002")])

    def test_boundary_exactly_at_policy_limit_is_clean(self):
        p = Policy.from_doc({"vaults": {"v": {"max_age_days": 153}}})
        self.assertEqual(analysis.analyze(inv(aes("k", "v", "2026-05-01")), policy=p), [])
        p = Policy.from_doc({"vaults": {"v": {"max_age_days": 152}}})
        self.assertEqual(rules(analysis.analyze(inv(aes("k", "v", "2026-05-01")), policy=p)), [("k", "KM002")])

    def test_prefix_beats_vault(self):
        p = Policy.from_doc({"vaults": {"v": {"max_age_days": 400}}, "key_prefixes": {"orders-": {"max_age_days": 60}}})
        fs = analysis.analyze(inv(aes("orders-a", "v", "2026-05-01"), aes("other", "v", "2026-05-01")), policy=p)
        self.assertEqual(rules(fs), [("orders-a", "KM002")])

    def test_longest_prefix_wins(self):
        p = Policy.from_doc({"key_prefixes": {"orders-": {"max_age_days": 60}, "orders-archive-": {"max_age_days": 400}}})
        fs = analysis.analyze(inv(aes("orders-archive-1", "v", "2026-05-01"), aes("orders-live", "v", "2026-05-01")), policy=p)
        self.assertEqual(rules(fs), [("orders-live", "KM002")])

    def test_vault_beats_default_and_default_beats_cli(self):
        p = Policy.from_doc({"default": {"max_age_days": 100}, "vaults": {"v": {"max_age_days": 200}}})
        fs = analysis.analyze(inv(aes("a", "v", "2026-05-01"), aes("b", "w", "2026-05-01")), max_age_days=500, policy=p)
        self.assertEqual(rules(fs), [("b", "KM002")])

    def test_partial_override_falls_through_for_other_limits(self):
        # prefix sets only max_old_versions; max_age_days still comes from the vault entry
        p = Policy.from_doc({"vaults": {"v": {"max_age_days": 100}}, "key_prefixes": {"x-": {"max_old_versions": 9}}})
        fs = analysis.analyze(inv(aes("x-1", "v", "2026-05-01")), policy=p)
        self.assertEqual(rules(fs), [("x-1", "KM002")])

    def test_message_reports_effective_limit(self):
        p = Policy.from_doc({"vaults": {"v": {"max_age_days": 100}}})
        f = analysis.analyze(inv(aes("k", "v", "2026-05-01")), policy=p)[0]
        self.assertIn("limit 100", f.message)

    def test_idle_disabled_and_old_versions_limits(self):
        dis = {"name": "d", "vault": "v", "algorithm": "AES", "protection": "HSM", "state": "DISABLED",
               "created": "2025-01-01", "disabled_since": "2026-08-01"}  # 61 days
        self.assertEqual(analysis.analyze(inv(dis)), [])
        p = Policy.from_doc({"vaults": {"v": {"idle_disabled_days": 30}}})
        self.assertEqual(rules(analysis.analyze(inv(dis), policy=p)), [("d", "KM008")])

    def test_empty_policy_changes_nothing(self):
        base = analysis.analyze(model.load_file(EX))
        self.assertEqual(analysis.analyze(model.load_file(EX), policy=Policy.from_doc({})), base)

    def test_example_policy_loads_and_changes_results(self):
        pol = Policy.load_file(POL)
        a = analysis.analyze(model.load_file(EX))
        b = analysis.analyze(model.load_file(EX), policy=pol)
        self.assertNotEqual(rules(a), rules(b))


class PolicyValidationTests(unittest.TestCase):
    def bad(self, doc):
        with self.assertRaises(model.ModelError):
            Policy.from_doc(doc)

    def test_bad_inputs(self):
        self.bad([])
        self.bad({"surprise": {}})
        self.bad({"default": {}})
        self.bad({"default": {"max_age": 5}})
        self.bad({"default": {"max_age_days": "90"}})
        self.bad({"default": {"max_age_days": True}})
        self.bad({"default": {"max_age_days": 0}})
        self.bad({"default": {"max_age_days": -5}})
        self.bad({"vaults": []})
        self.bad({"vaults": {"v": {}}})
        self.bad({"key_prefixes": {"": {"max_age_days": 5}}})

    def test_zero_old_versions_is_allowed(self):
        Policy.from_doc({"default": {"max_old_versions": 0}})


class CliPolicyTests(unittest.TestCase):
    def run_cli(self, argv):
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            code = main(argv)
        return code, err.getvalue()

    def test_cli_without_policy_unchanged(self):
        self.assertEqual(self.run_cli([EX])[0], 0)

    def test_cli_with_policy_and_fail_on(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "p.json")
            with open(p, "w") as f:
                json.dump({"default": {"max_age_days": 1}}, f)
            self.assertEqual(self.run_cli([EX, "--policy", p])[0], 0)
            self.assertEqual(self.run_cli([EX, "--policy", p, "--fail-on", "medium"])[0], 2)

    def test_cli_bad_policy_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "p.json")
            with open(p, "w") as f:
                f.write('{"default": {"max_age_days": 0}}')
            code, err = self.run_cli([EX, "--policy", p])
            self.assertEqual(code, 1)
            self.assertIn("max_age_days", err)
            with open(p, "w") as f:
                f.write("not json")
            self.assertEqual(self.run_cli([EX, "--policy", p])[0], 1)
        self.assertEqual(self.run_cli([EX, "--policy", "/nonexistent.json"])[0], 1)


if __name__ == "__main__":
    unittest.main()
