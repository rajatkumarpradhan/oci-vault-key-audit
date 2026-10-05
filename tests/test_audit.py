import copy
import json
import os
import tempfile
import unittest

from vault_audit import analysis, model
from vault_audit.cli import main

EX = os.path.join(os.path.dirname(__file__), "..", "examples", "synthetic.json")
with open(EX, encoding="utf-8") as f:
    BASE = json.load(f)


def key(d, name):
    return next(k for k in d["keys"] if k["name"] == name)


def run(mut=None, **kw):
    d = copy.deepcopy(BASE)
    if mut:
        mut(d)
    return analysis.analyze(model.load(d), **kw)


def rules(fs, name=None):
    return sorted(f.rule for f in fs if name is None or f.key == name)


def one_key(**over):
    k = dict(name="k", vault="v", algorithm="AES", protection="HSM", state="ENABLED",
             created="2026-09-01", auto_rotation_days=90)
    k.update(over)
    return {"as_of": "2026-10-01", "keys": [k]}


def an(doc, **kw):
    return analysis.analyze(model.load(doc), **kw)


class ModelTests(unittest.TestCase):
    def bad(self, doc):
        with self.assertRaises(model.ModelError):
            model.load(doc)

    def test_not_object(self):
        self.bad([])

    def test_missing_as_of(self):
        self.bad({"keys": []})

    def test_bad_algorithm(self):
        self.bad(one_key(algorithm="DES"))

    def test_bad_protection(self):
        self.bad(one_key(protection="CLOUD"))

    def test_bad_state(self):
        self.bad(one_key(state="MAYBE"))

    def test_future_created(self):
        self.bad(one_key(created="2027-01-01"))

    def test_rotated_before_created(self):
        self.bad(one_key(last_rotated="2026-08-01"))

    def test_bad_interval(self):
        self.bad(one_key(auto_rotation_days=0))
        self.bad(one_key(auto_rotation_days=True))

    def test_asymmetric_auto_rotation_rejected(self):
        self.bad(one_key(algorithm="RSA", auto_rotation_days=90))

    def test_duplicate_key(self):
        d = one_key()
        d["keys"].append(copy.deepcopy(d["keys"][0]))
        self.bad(d)

    def test_same_name_other_vault_ok(self):
        d = one_key()
        k2 = copy.deepcopy(d["keys"][0])
        k2["vault"] = "w"
        d["keys"].append(k2)
        self.assertEqual(len(model.load(d).keys), 2)

    def test_bad_sensitivity(self):
        self.bad(one_key(usage=[{"resource": "r", "sensitivity": "extreme"}]))

    def test_bad_date_format(self):
        self.bad(one_key(created="soon"))


class RuleTests(unittest.TestCase):
    def test_example_expected(self):
        fs = run()
        self.assertEqual(rules(fs, "legacy-bucket-key"), ["KM001", "KM003", "KM006"])
        self.assertEqual(rules(fs, "logs-key"), ["KM002", "KM004", "KM005"])
        self.assertEqual(rules(fs, "old-archive-key"), ["KM007"])
        self.assertEqual(rules(fs, "unused-test-key"), ["KM008"])
        self.assertEqual(rules(fs, "decommissioned-key"), ["KM009"])
        self.assertEqual(rules(fs, "retired-key"), ["KM009"])

    def test_healthy_keys_clean(self):
        fs = run()
        for n in ("orders-db-key", "signing-key", "fresh-key"):
            self.assertEqual(rules(fs, n), [], n)

    def test_age_boundary(self):
        # as_of 2026-10-01; created exactly 365 days before is not over the limit
        self.assertEqual(rules(an(one_key(created="2025-10-01"))), [])
        self.assertEqual(rules(an(one_key(created="2025-09-30"))), ["KM001"])

    def test_rotation_resets_age(self):
        self.assertEqual(rules(an(one_key(created="2020-01-01", last_rotated="2026-09-01"))), [])

    def test_never_rotated_unused_is_medium(self):
        fs = an(one_key(created="2020-01-01"))
        self.assertEqual([(f.rule, f.severity) for f in fs], [("KM001", "medium")])
        fs = an(one_key(created="2020-01-01", usage=[{"resource": "r"}]))
        self.assertEqual([(f.rule, f.severity) for f in fs], [("KM001", "high")])

    def test_asymmetric_not_flagged_for_auto_rotation(self):
        d = one_key(algorithm="RSA")
        del d["keys"][0]["auto_rotation_days"]
        self.assertEqual(rules(an(d)), [])

    def test_symmetric_without_auto_rotation(self):
        d = one_key()
        del d["keys"][0]["auto_rotation_days"]
        self.assertEqual(rules(an(d)), ["KM003"])

    def test_custom_max_age(self):
        d = one_key(created="2026-03-01")
        self.assertEqual(rules(an(d)), [])
        self.assertEqual(rules(an(d, max_age_days=100)), ["KM001"])

    def test_interval_rule_follows_limit(self):
        self.assertEqual(rules(an(one_key(auto_rotation_days=200), max_age_days=100)), ["KM004"])

    def test_old_versions_boundary(self):
        vs = lambda n: [{"id": f"v{i}", "state": "ENABLED", "created": "2026-09-01"} for i in range(n)]
        self.assertEqual(rules(an(one_key(versions=vs(4)))), [])   # 3 old + current
        self.assertEqual(rules(an(one_key(versions=vs(5)))), ["KM005"])

    def test_disabled_old_versions_not_counted(self):
        vs = [{"id": f"v{i}", "state": "DISABLED", "created": "2026-09-01"} for i in range(8)]
        vs.append({"id": "cur", "state": "ENABLED", "created": "2026-09-02"})
        self.assertEqual(rules(an(one_key(versions=vs))), [])

    def test_software_key_low_sensitivity_ok(self):
        self.assertEqual(rules(an(one_key(protection="SOFTWARE", usage=[{"resource": "r", "sensitivity": "normal"}]))), [])

    def test_inactive_usage_ignored(self):
        d = one_key(protection="SOFTWARE", usage=[{"resource": "r", "sensitivity": "high", "active": False}])
        self.assertEqual(rules(an(d)), [])

    def test_disabled_idle_boundary(self):
        d = lambda s: one_key(state="DISABLED", disabled_since=s)
        self.assertEqual(rules(an(d("2026-07-03"))), [])          # 90 days
        self.assertEqual(rules(an(d("2026-07-02"))), ["KM008"])   # 91 days

    def test_deletion_warning_window(self):
        d = lambda s: one_key(state="PENDING_DELETION", deletion_date=s)
        self.assertEqual(rules(an(d("2026-10-08"))), ["KM009"])
        self.assertEqual(rules(an(d("2026-10-09"))), [])

    def test_sorted_by_severity(self):
        sev = [analysis.SEV[f.severity] for f in run()]
        self.assertEqual(sev, sorted(sev))


class CliTests(unittest.TestCase):
    def test_report(self):
        with tempfile.TemporaryDirectory() as t:
            out = os.path.join(t, "r.json")
            self.assertEqual(main([EX, "--output", out]), 0)
            with open(out, encoding="utf-8") as f:
                rep = json.load(f)
        self.assertEqual(len(rep["findings"]), 10)
        self.assertIn("Not tested against a live tenancy", rep["disclaimer"])

    def test_fail_on(self):
        self.assertEqual(main([EX, "--fail-on", "high"]), 2)

    def test_bad_file(self):
        self.assertEqual(main(["/nope.json"]), 1)

    def test_bad_limit(self):
        self.assertEqual(main([EX, "--max-age-days", "0"]), 1)


if __name__ == "__main__":
    unittest.main()
