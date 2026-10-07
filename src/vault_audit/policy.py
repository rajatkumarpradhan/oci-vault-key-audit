"""Per-vault and per-key-prefix limits from a small JSON policy file.

{
  "default":      {"max_age_days": 365},
  "vaults":       {"prod-vault": {"max_age_days": 90}},
  "key_prefixes": {"orders-": {"max_age_days": 60, "max_old_versions": 1}}
}

Precedence, most specific wins: longest matching key-name prefix, then vault,
then "default", then the CLI values (or built-in defaults). Only the limits
named in an entry are overridden; the rest fall through.
"""
from __future__ import annotations

import json

from .model import ModelError

LIMITS = ("max_age_days", "idle_disabled_days", "max_old_versions")
TOP = {"default", "vaults", "key_prefixes"}


def _limits(d, where: str) -> dict:
    if not isinstance(d, dict) or not d:
        raise ModelError(f"policy {where}: must be a non-empty object of limits")
    out = {}
    for k, v in d.items():
        if k not in LIMITS:
            raise ModelError(f"policy {where}: unknown limit {k!r} (allowed: {', '.join(LIMITS)})")
        if isinstance(v, bool) or not isinstance(v, int):
            raise ModelError(f"policy {where}.{k}: must be an integer")
        if v < (0 if k == "max_old_versions" else 1):
            raise ModelError(f"policy {where}.{k}: out of range")
        out[k] = v
    return out


class Policy:
    def __init__(self, default=None, vaults=None, prefixes=None):
        self.default = default or {}
        self.vaults = vaults or {}
        self.prefixes = prefixes or {}

    @classmethod
    def from_doc(cls, doc) -> "Policy":
        if not isinstance(doc, dict):
            raise ModelError("policy must be a JSON object")
        extra = set(doc) - TOP
        if extra:
            raise ModelError(f"policy: unknown section(s) {sorted(extra)}")
        default = _limits(doc["default"], "default") if "default" in doc else {}
        vaults, prefixes = {}, {}
        for section, target in (("vaults", vaults), ("key_prefixes", prefixes)):
            sec = doc.get(section, {})
            if not isinstance(sec, dict):
                raise ModelError(f"policy {section}: must be an object")
            for name, lim in sec.items():
                if not name:
                    raise ModelError(f"policy {section}: empty name")
                target[name] = _limits(lim, f"{section}[{name!r}]")
        return cls(default, vaults, prefixes)

    @classmethod
    def load_file(cls, path: str) -> "Policy":
        with open(path, encoding="utf-8") as f:
            return cls.from_doc(json.load(f))

    def limits_for(self, key, base: dict) -> dict:
        """Effective limits for one key. `base` holds the CLI/built-in values."""
        eff = dict(base)
        eff.update(self.default)
        eff.update(self.vaults.get(key.vault, {}))
        match = [p for p in self.prefixes if key.name.startswith(p)]
        if match:
            eff.update(self.prefixes[max(match, key=len)])
        return eff
