"""Rules KM001-KM009. Findings are review priorities from a snapshot, not proof of a weakness."""
from __future__ import annotations

from dataclasses import asdict, dataclass

from .model import ASYMMETRIC, Inventory, Key

SEV = {"high": 0, "medium": 1, "low": 2}
# Policy defaults. These are this tool's assumptions, not Oracle requirements: set your own.
DEFAULT_MAX_AGE_DAYS = 365
DEFAULT_IDLE_DISABLED_DAYS = 90
DEFAULT_MAX_OLD_ENABLED_VERSIONS = 3
DELETION_WARN_DAYS = 7


@dataclass
class Finding:
    rule: str
    severity: str
    key: str
    vault: str
    message: str
    evidence: dict

    def to_dict(self):
        return asdict(self)


def _age(inv: Inventory, k: Key) -> int:
    """Days since the key was last rotated (or created if never rotated)."""
    return (inv.as_of - (k.last_rotated or k.created)).days


def analyze(inv: Inventory, max_age_days: int = DEFAULT_MAX_AGE_DAYS,
            idle_days: int = DEFAULT_IDLE_DISABLED_DAYS,
            max_old_versions: int = DEFAULT_MAX_OLD_ENABLED_VERSIONS, policy=None) -> list[Finding]:
    out: list[Finding] = []
    base = {"max_age_days": max_age_days, "idle_disabled_days": idle_days, "max_old_versions": max_old_versions}

    def add(rule, sev, k, msg, ev=None):
        out.append(Finding(rule, sev, k.name, k.vault, msg, ev or {}))

    for k in inv.keys:
        lim = policy.limits_for(k, base) if policy else base
        max_age_days, idle_days, max_old_versions = lim["max_age_days"], lim["idle_disabled_days"], lim["max_old_versions"]
        active_use = [u for u in k.usage if u.active]
        if k.state == "ENABLED":
            age = _age(inv, k)
            if age > max_age_days:
                if k.last_rotated is None:
                    add("KM001", "high" if active_use else "medium", k,
                        f"Never rotated; {age} days old (limit {max_age_days}).", {"age_days": age})
                else:
                    add("KM002", "medium", k,
                        f"Last rotated {age} days ago (limit {max_age_days}).", {"age_days": age})
            if k.algorithm not in ASYMMETRIC:
                if k.auto_rotation_days is None:
                    add("KM003", "medium", k, "No automatic rotation configured on a symmetric key.")
                elif k.auto_rotation_days > max_age_days:
                    add("KM004", "low", k,
                        f"Auto-rotation interval {k.auto_rotation_days}d is longer than the {max_age_days}d limit.",
                        {"interval_days": k.auto_rotation_days})
            old_enabled = [v for v in k.versions if v.state == "ENABLED"][:-1]
            if len(old_enabled) > max_old_versions:
                add("KM005", "low", k,
                    f"{len(old_enabled)} older versions still enabled (limit {max_old_versions}). "
                    "Older versions may be needed to decrypt existing data: check before disabling.",
                    {"old_enabled": len(old_enabled)})
            sensitive = [u for u in active_use if u.sensitivity == "high"]
            if k.protection == "SOFTWARE" and sensitive:
                add("KM006", "medium", k,
                    f"Software-protected key used by high-sensitivity resource(s): {', '.join(u.resource for u in sensitive)}. "
                    "Consider HSM protection if your policy requires it.",
                    {"resources": [u.resource for u in sensitive]})
        elif k.state == "DISABLED":
            if active_use:
                add("KM007", "high", k,
                    f"Disabled but still used by {len(active_use)} active resource(s): "
                    f"{', '.join(u.resource for u in active_use)}. Operations that need the key will fail.",
                    {"resources": [u.resource for u in active_use]})
            elif k.disabled_since and (inv.as_of - k.disabled_since).days > idle_days:
                d = (inv.as_of - k.disabled_since).days
                add("KM008", "low", k, f"Disabled {d} days with no active use: candidate for scheduled deletion after review.",
                    {"disabled_days": d})
        elif k.state in ("PENDING_DELETION", "SCHEDULING_DELETION"):
            if active_use:
                add("KM009", "high", k,
                    f"Pending deletion but still used by {len(active_use)} active resource(s): "
                    f"{', '.join(u.resource for u in active_use)}. Data encrypted with it becomes unrecoverable after deletion.",
                    {"resources": [u.resource for u in active_use], "deletion_date": str(k.deletion_date)})
            elif k.deletion_date and 0 <= (k.deletion_date - inv.as_of).days <= DELETION_WARN_DAYS:
                add("KM009", "low", k,
                    f"Deletion in {(k.deletion_date - inv.as_of).days} day(s); confirm nothing needs it.",
                    {"deletion_date": str(k.deletion_date)})
    out.sort(key=lambda f: (SEV[f.severity], f.rule, f.vault, f.key))
    return out
