"""Convert a flat CSV list of keys into the inventory JSON the audit reads.

Required columns: name, vault, algorithm, protection, state, created, last_rotated.
Optional columns: auto_rotation_days, disabled_since, deletion_date.
Versions and usage are not part of a flat export, so keys come out with neither;
rules that need them (KM005 to KM009 usage checks) see only what the CSV carries.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import sys

from . import model

REQUIRED = ["name", "vault", "algorithm", "protection", "state", "created", "last_rotated"]
OPTIONAL = ["auto_rotation_days", "disabled_since", "deletion_date"]


class ImportErrorList(model.ModelError):
    def __init__(self, errors):
        self.errors = errors
        super().__init__("; ".join(errors))


def rows_to_doc(text: str, as_of: str) -> dict:
    reader = csv.DictReader(io.StringIO(text))
    header = [h.strip().lower() for h in (reader.fieldnames or [])]
    missing = [c for c in REQUIRED if c not in header]
    if missing:
        raise ImportErrorList([f"missing column(s): {', '.join(missing)}"])
    reader.fieldnames = header
    keys, errors = [], []
    for n, row in enumerate(reader, start=2):  # row 1 is the header
        if None in row:
            errors.append(f"row {n}: more fields than columns")
            continue
        vals = {k: (v or "").strip() for k, v in row.items() if k}
        if not any(vals.values()):
            continue  # blank line
        k = {c: vals.get(c, "") for c in REQUIRED}
        for c in OPTIONAL:
            if vals.get(c):
                k[c] = vals[c]
        if not k["last_rotated"]:
            del k["last_rotated"]
        if "auto_rotation_days" in k:
            try:
                k["auto_rotation_days"] = int(k["auto_rotation_days"])
            except ValueError:
                errors.append(f"row {n}: auto_rotation_days must be a whole number")
                continue
        keys.append((n, k))
    doc = {"as_of": as_of, "keys": [k for _, k in keys]}
    # Validate each row alone so errors carry the CSV row number.
    for n, k in keys:
        try:
            model.load({"as_of": as_of, "keys": [k]})
        except model.ModelError as e:
            errors.append(f"row {n}: {e}")
    seen = {}
    for n, k in keys:
        ident = (k["vault"], k["name"])
        if ident in seen:
            errors.append(f"row {n}: duplicate key {k['name']!r} in vault {k['vault']!r} (first at row {seen[ident]})")
        else:
            seen[ident] = n
    if errors:
        raise ImportErrorList(errors)
    if not doc["keys"]:
        raise ImportErrorList(["no data rows"])
    return doc


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="vault-import", description="Convert a flat key CSV to the inventory JSON (synthetic/exported data).")
    ap.add_argument("csv")
    ap.add_argument("--as-of", required=True, help="date ages are measured from, YYYY-MM-DD")
    ap.add_argument("--output", help="write JSON here instead of stdout")
    a = ap.parse_args(argv)
    try:
        with open(a.csv, encoding="utf-8-sig", newline="") as f:
            doc = rows_to_doc(f.read(), a.as_of)
        model.load(doc)
    except ImportErrorList as e:
        for m in e.errors:
            print(f"error: {m}", file=sys.stderr)
        return 1
    except (OSError, model.ModelError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    out = json.dumps(doc, indent=1)
    if a.output:
        with open(a.output, "w", encoding="utf-8") as fh:
            fh.write(out + "\n")
    else:
        print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
