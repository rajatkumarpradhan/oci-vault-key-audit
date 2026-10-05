"""Load and validate a simplified key-inventory JSON (synthetic or hand-exported)."""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date

SYMMETRIC = {"AES"}
ASYMMETRIC = {"RSA", "ECDSA"}
STATES = {"ENABLED", "DISABLED", "PENDING_DELETION", "SCHEDULING_DELETION", "DELETED"}
PROTECTION = {"HSM", "SOFTWARE"}
SENSITIVITY = {"low", "normal", "high"}


class ModelError(ValueError):
    pass


@dataclass
class Version:
    id: str
    state: str
    created: date


@dataclass
class Usage:
    resource: str
    kind: str
    sensitivity: str = "normal"
    active: bool = True


@dataclass
class Key:
    name: str
    vault: str
    algorithm: str
    protection: str
    state: str
    created: date
    last_rotated: date | None = None
    auto_rotation_days: int | None = None
    disabled_since: date | None = None
    deletion_date: date | None = None
    versions: list[Version] = field(default_factory=list)
    usage: list[Usage] = field(default_factory=list)


@dataclass
class Inventory:
    as_of: date
    keys: list[Key]


def _d(v, what: str, required: bool = True):
    if v in (None, ""):
        if required:
            raise ModelError(f"{what} is required")
        return None
    try:
        return date.fromisoformat(str(v)[:10])
    except ValueError:
        raise ModelError(f"{what}: bad date {v!r}")


def load(doc: dict) -> Inventory:
    if not isinstance(doc, dict) or "keys" not in doc:
        raise ModelError("inventory must be an object with a 'keys' list")
    as_of = _d(doc.get("as_of"), "as_of")
    keys, seen = [], set()
    for i, k in enumerate(doc["keys"]):
        n = k.get("name")
        if not n:
            raise ModelError(f"keys[{i}]: name is required")
        if (k.get("vault"), n) in seen:
            raise ModelError(f"duplicate key {n!r} in vault {k.get('vault')!r}")
        seen.add((k.get("vault"), n))
        alg = str(k.get("algorithm", "")).upper()
        if alg not in SYMMETRIC | ASYMMETRIC:
            raise ModelError(f"{n}: algorithm must be one of {sorted(SYMMETRIC | ASYMMETRIC)}")
        prot = str(k.get("protection", "")).upper()
        if prot not in PROTECTION:
            raise ModelError(f"{n}: protection must be HSM or SOFTWARE")
        st = str(k.get("state", "")).upper()
        if st not in STATES:
            raise ModelError(f"{n}: unknown state {k.get('state')!r}")
        created = _d(k.get("created"), f"{n}.created")
        last = _d(k.get("last_rotated"), f"{n}.last_rotated", False)
        for label, d in (("created", created), ("last_rotated", last)):
            if d and d > as_of:
                raise ModelError(f"{n}.{label} is after as_of")
        if last and last < created:
            raise ModelError(f"{n}.last_rotated is before created")
        ar = k.get("auto_rotation_days")
        if ar is not None and (isinstance(ar, bool) or not isinstance(ar, int) or ar < 1):
            raise ModelError(f"{n}.auto_rotation_days must be a positive integer")
        if ar is not None and alg in ASYMMETRIC:
            raise ModelError(f"{n}: auto_rotation_days is only modelled for symmetric (AES) keys")
        vs = [Version(str(v["id"]), str(v["state"]).upper(), _d(v.get("created"), f"{n}.version.created"))
              for v in k.get("versions", [])]
        us = []
        for u in k.get("usage", []):
            s = u.get("sensitivity", "normal")
            if s not in SENSITIVITY:
                raise ModelError(f"{n}: usage sensitivity must be one of {sorted(SENSITIVITY)}")
            us.append(Usage(str(u["resource"]), str(u.get("kind", "resource")), s, bool(u.get("active", True))))
        keys.append(Key(n, str(k.get("vault", "")), alg, prot, st, created, last, ar,
                        _d(k.get("disabled_since"), f"{n}.disabled_since", False),
                        _d(k.get("deletion_date"), f"{n}.deletion_date", False), vs, us))
    return Inventory(as_of, keys)


def load_file(path: str) -> Inventory:
    with open(path, encoding="utf-8") as f:
        return load(json.load(f))
