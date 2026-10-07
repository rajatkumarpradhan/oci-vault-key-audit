# oci-vault-key-audit

Offline review of OCI Vault key rotation and lifecycle from an exported key inventory: keys that were never rotated, rotation intervals longer than policy, disabled or pending-deletion keys that something still uses, and software keys protecting high-sensitivity resources.

**Scope, stated plainly.** Portfolio project. It reads a simplified JSON inventory. The bundled data is synthetic. It has not been run against a real tenancy, calls no OCI API, reads no key material and spends nothing. Findings are review priorities from a snapshot, not proof of a weakness.

## Usage

```
python -m pip install -e .
vault-audit examples/synthetic.json --output report.json
vault-audit examples/synthetic.json --max-age-days 180 --fail-on high   # exit code 2 on any high finding
vault-import examples/synthetic_keys.csv --as-of 2026-10-01 --output inventory.json   # flat CSV to inventory JSON
python -m unittest discover -s tests -v
```

## CSV importer

`vault-import` turns a flat CSV into the inventory JSON, so the audit can be tried without hand-writing JSON. Required columns: `name, vault, algorithm, protection, state, created, last_rotated`. Optional: `auto_rotation_days, disabled_since, deletion_date`. Header case and spaces are ignored. Leave `last_rotated` empty for a key that was never rotated. `--as-of YYYY-MM-DD` sets the date ages are measured from.

Every row is validated with the same rules as the JSON loader. Malformed rows are all reported with their CSV row number (row 1 is the header) and nothing is written; the exit code is 1. A flat CSV carries no key versions or resource usage, so rules that depend on them (KM005 and the usage checks in KM006 to KM009) only see what the CSV has. The bundled `examples/synthetic_keys.csv` is synthetic.

The input has `as_of` (the date ages are measured from, so results are reproducible) and a list of `keys`, each with vault, algorithm (AES, RSA, ECDSA), protection (HSM or SOFTWARE), state, created and last-rotated dates, an optional `auto_rotation_days` (AES only), key versions, and `usage` entries naming the resources that use the key and how sensitive they are.

## Rules

| Rule | Severity | Meaning |
|---|---|---|
| KM001 | high / medium | Enabled key never rotated and older than the limit (high when something actively uses it) |
| KM002 | medium | Enabled key last rotated longer ago than the limit |
| KM003 | medium | Symmetric (AES) key with no automatic rotation configured |
| KM004 | low | Auto-rotation interval longer than the limit |
| KM005 | low | More than N older versions still enabled (older versions may be needed to decrypt existing data) |
| KM006 | medium | Software-protected key used by a high-sensitivity resource |
| KM007 | high | Disabled key still used by an active resource |
| KM008 | low | Disabled key with no active use for over 90 days: deletion candidate after review |
| KM009 | high / low | Pending-deletion key still used (high), or deletion within 7 days (low) |

Asymmetric keys are not flagged for missing auto-rotation, and an `auto_rotation_days` on one is rejected: that setting is only modelled for AES keys. Resources marked `"active": false` are ignored.

## Policy file

`--policy policy.json` sets different limits per vault or key-name prefix instead of one global value (see `examples/policy.json`):

```
{"default": {"max_age_days": 365},
 "vaults": {"prod-vault": {"max_age_days": 180}},
 "key_prefixes": {"orders-": {"max_age_days": 60}}}
```

Settable limits: `max_age_days`, `idle_disabled_days`, `max_old_versions`. Precedence, most specific first: longest matching key-name prefix, then vault, then `default`, then the CLI flags or built-in defaults. An entry overrides only the limits it names. Unknown sections or limits, non-integers and out-of-range values are rejected with exit code 1. Without `--policy` behaviour is unchanged. Findings report the limit that was actually applied.

## Limits

- The defaults (365 day rotation limit, 90 day idle-disabled window, 3 older enabled versions, 7 day deletion warning) are this tool's assumptions, not Oracle requirements. Pass your own with `--max-age-days`, `--idle-disabled-days` and `--max-old-versions`. Check current Oracle documentation for what auto-rotation supports before relying on a number.
- "Rotated" means the date you put in the inventory. Nothing verifies it.
- The `usage` list is only as complete as the inventory: a key with no listed usage may still be in use somewhere the export missed.
- Vault-level settings (replication, backup, policies, IAM) are not modelled.
- No exporter from a real tenancy exists; only synthetic inventories were tested.

## Tests

69 unit tests cover validation, every rule and its boundary (for example a key exactly 365 days old), the severity split on KM001, asymmetric keys not being flagged for auto-rotation, disabled versions not counted, the CLI, the CSV importer (malformed rows, duplicates, missing columns), and the policy file (precedence, partial overrides, boundaries, bad input). Three of the nine example keys are deliberately healthy and the tests require zero findings for them. CI runs on Python 3.10, 3.11 and 3.12.

## License

MIT
