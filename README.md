# oci-vault-key-audit

Offline review of OCI Vault key rotation and lifecycle from an exported key inventory: keys that were never rotated, rotation intervals longer than policy, disabled or pending-deletion keys that something still uses, and software keys protecting high-sensitivity resources.

**Scope, stated plainly.** Portfolio project. It reads a simplified JSON inventory. The bundled data is synthetic. It has not been run against a real tenancy, calls no OCI API, reads no key material and spends nothing. Findings are review priorities from a snapshot, not proof of a weakness.

## Usage

```
python -m pip install -e .
vault-audit examples/synthetic.json --output report.json
vault-audit examples/synthetic.json --max-age-days 180 --fail-on high   # exit code 2 on any high finding
python -m unittest discover -s tests -v
```

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

## Limits

- The defaults (365 day rotation limit, 90 day idle-disabled window, 3 older enabled versions, 7 day deletion warning) are this tool's assumptions, not Oracle requirements. Pass your own with `--max-age-days`, `--idle-disabled-days` and `--max-old-versions`. Check current Oracle documentation for what auto-rotation supports before relying on a number.
- "Rotated" means the date you put in the inventory. Nothing verifies it.
- The `usage` list is only as complete as the inventory: a key with no listed usage may still be in use somewhere the export missed.
- Vault-level settings (replication, backup, policies, IAM) are not modelled.
- No exporter from a real tenancy exists; only synthetic inventories were tested.

## Tests

33 unit tests cover validation, every rule and its boundary (for example a key exactly 365 days old), the severity split on KM001, asymmetric keys not being flagged for auto-rotation, disabled versions not counted, and the CLI. Three of the nine example keys are deliberately healthy and the tests require zero findings for them. CI runs on Python 3.10, 3.11 and 3.12.

## License

MIT
