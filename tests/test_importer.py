import contextlib
import io
import json
import os
import tempfile
import unittest

from vault_audit import analysis, model
from vault_audit.importer import ImportErrorList, main, rows_to_doc

EX = os.path.join(os.path.dirname(__file__), "..", "examples", "synthetic_keys.csv")
HDR = "name,vault,algorithm,protection,state,created,last_rotated\n"
GOOD = "k1,v1,AES,HSM,ENABLED,2026-01-01,2026-06-01\n"


def errs(text, as_of="2026-10-01"):
    try:
        rows_to_doc(text, as_of)
    except ImportErrorList as e:
        return e.errors
    return []


class ImporterTests(unittest.TestCase):
    def test_example_converts_and_loads(self):
        with open(EX, encoding="utf-8") as f:
            doc = rows_to_doc(f.read(), "2026-10-01")
        inv = model.load(doc)
        self.assertEqual(len(inv.keys), 5)

    def test_types_and_optional_columns(self):
        with open(EX, encoding="utf-8") as f:
            doc = rows_to_doc(f.read(), "2026-10-01")
        k = {x["name"]: x for x in doc["keys"]}
        self.assertEqual(k["orders-db-key"]["auto_rotation_days"], 90)
        self.assertEqual(k["unused-test-key"]["disabled_since"], "2026-03-01")
        self.assertNotIn("last_rotated", k["legacy-bucket-key"])
        self.assertNotIn("deletion_date", k["orders-db-key"])

    def test_healthy_keys_produce_no_findings(self):
        doc = rows_to_doc(HDR.strip() + ",auto_rotation_days\nok,v1,AES,HSM,ENABLED,2026-06-01,2026-08-01,90\n", "2026-10-01")
        self.assertEqual(analysis.analyze(model.load(doc)), [])

    def test_never_rotated_old_key_is_found(self):
        doc = rows_to_doc(HDR + "old,v1,AES,HSM,ENABLED,2024-01-01,\n", "2026-10-01")
        self.assertIn("KM001", [f.rule for f in analysis.analyze(model.load(doc))])

    def test_missing_required_column(self):
        e = errs("name,vault,algorithm,protection,state,created\nk,v,AES,HSM,ENABLED,2026-01-01\n")
        self.assertEqual(len(e), 1)
        self.assertIn("last_rotated", e[0])

    def test_header_case_and_whitespace_tolerated(self):
        self.assertEqual(errs(" Name , VAULT ,Algorithm,protection,state,created,last_rotated\n" + GOOD), [])

    def test_bad_date_reports_row_number(self):
        e = errs(HDR + GOOD + "k2,v1,AES,HSM,ENABLED,2026-13-45,\n")
        self.assertEqual(len(e), 1)
        self.assertTrue(e[0].startswith("row 3:"))

    def test_bad_algorithm_and_state(self):
        e = errs(HDR + "a,v,DES,HSM,ENABLED,2026-01-01,\nb,v,AES,HSM,BROKEN,2026-01-01,\n")
        self.assertEqual([x[:6] for x in e], ["row 2:", "row 3:"])

    def test_all_errors_reported_together(self):
        e = errs(HDR + "a,v,DES,HSM,ENABLED,2026-01-01,\nb,v,AES,XXX,ENABLED,2026-01-01,\n")
        self.assertEqual(len(e), 2)

    def test_non_numeric_rotation_days(self):
        e = errs("name,vault,algorithm,protection,state,created,last_rotated,auto_rotation_days\nk,v,AES,HSM,ENABLED,2026-01-01,,often\n")
        self.assertIn("auto_rotation_days", e[0])

    def test_rotation_days_on_asymmetric_key_rejected(self):
        e = errs("name,vault,algorithm,protection,state,created,last_rotated,auto_rotation_days\nk,v,RSA,HSM,ENABLED,2026-01-01,,30\n")
        self.assertEqual(len(e), 1)

    def test_duplicate_key_in_same_vault(self):
        e = errs(HDR + GOOD + GOOD)
        self.assertIn("duplicate", e[0])
        self.assertIn("row 3", e[0])

    def test_same_name_in_different_vaults_is_fine(self):
        self.assertEqual(errs(HDR + GOOD + GOOD.replace("v1", "v2")), [])

    def test_too_many_fields_in_row(self):
        e = errs(HDR + GOOD.strip() + ",extra\n")
        self.assertIn("more fields", e[0])

    def test_future_date_rejected(self):
        e = errs(HDR + "k,v,AES,HSM,ENABLED,2027-01-01,\n")
        self.assertIn("after as_of", e[0])

    def test_blank_lines_skipped_but_empty_file_rejected(self):
        self.assertEqual(errs(HDR + "\n" + GOOD + "\n"), [])
        self.assertEqual(errs(HDR), ["no data rows"])

    def test_cli_writes_file_and_round_trips_into_audit(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "inv.json")
            self.assertEqual(main([EX, "--as-of", "2026-10-01", "--output", out]), 0)
            inv = model.load_file(out)
            self.assertEqual(len(inv.keys), 5)
            self.assertTrue(analysis.analyze(inv))

    def test_cli_failure_exit_code_and_message(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "bad.csv")
            with open(p, "w", encoding="utf-8") as f:
                f.write(HDR + "k,v,AES,HSM,ENABLED,nope,\n")
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                self.assertEqual(main([p, "--as-of", "2026-10-01"]), 1)
            self.assertIn("row 2", buf.getvalue())

    def test_cli_missing_file_and_bad_as_of(self):
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            self.assertEqual(main(["/nonexistent.csv", "--as-of", "2026-10-01"]), 1)
            self.assertEqual(main([EX, "--as-of", "yesterday"]), 1)

    def test_cli_stdout_is_valid_json(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(main([EX, "--as-of", "2026-10-01"]), 0)
        self.assertEqual(json.loads(out.getvalue())["as_of"], "2026-10-01")


if __name__ == "__main__":
    unittest.main()
