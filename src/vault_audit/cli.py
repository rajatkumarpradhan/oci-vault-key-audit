from __future__ import annotations

import argparse
import json
import sys

from . import analysis, model

DISCLAIMER = ("Review priorities from a snapshot of a simplified inventory. Policy limits are configurable "
              "assumptions, not Oracle requirements. Not tested against a live tenancy.")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="vault-audit", description="Offline OCI Vault key rotation and lifecycle review (synthetic/exported data).")
    ap.add_argument("inventory")
    ap.add_argument("--max-age-days", type=int, default=analysis.DEFAULT_MAX_AGE_DAYS)
    ap.add_argument("--idle-disabled-days", type=int, default=analysis.DEFAULT_IDLE_DISABLED_DAYS)
    ap.add_argument("--max-old-versions", type=int, default=analysis.DEFAULT_MAX_OLD_ENABLED_VERSIONS)
    ap.add_argument("--output")
    ap.add_argument("--fail-on", choices=["high", "medium", "low"])
    a = ap.parse_args(argv)
    try:
        if a.max_age_days < 1 or a.idle_disabled_days < 1 or a.max_old_versions < 0:
            raise ValueError("limits must be positive")
        inv = model.load_file(a.inventory)
    except (OSError, json.JSONDecodeError, model.ModelError, ValueError, KeyError, TypeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    fs = analysis.analyze(inv, a.max_age_days, a.idle_disabled_days, a.max_old_versions)
    for f in fs:
        print(f"[{f.severity.upper():6}] {f.rule} {f.vault}/{f.key}: {f.message}")
    print(f"{len(fs)} finding(s) across {len(inv.keys)} key(s).")
    if a.output:
        with open(a.output, "w", encoding="utf-8") as fh:
            json.dump({"as_of": str(inv.as_of), "disclaimer": DISCLAIMER,
                       "findings": [f.to_dict() for f in fs]}, fh, indent=1)
    if a.fail_on and any(analysis.SEV[f.severity] <= analysis.SEV[a.fail_on] for f in fs):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
