"""Tier 0: cheap, explainable rules over the extracted signals.

Every rule that fires adds a reason code. `block` rules are precise enough to quarantine on
their own, but only for senders with no history: an established correspondent is never
hard-blocked by a rule (sister companies have lookalike domains), the model decides instead.
`flag` rules only add a reason code. Severities were chosen from per-rule precision on the
training period (printed by `make train`).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Literal

Severity = Literal["block", "flag"]


@dataclass(frozen=True)
class Rule:
    code: str
    severity: Severity
    description: str
    fires: Callable[[dict[str, float]], bool]


RULES: list[Rule] = [
    Rule("AUTH_FAIL", "flag", "DMARC failed, or SPF and DKIM both failed",
         lambda f: f["dmarc_fail"] == 1 or f["auth_fail_count"] >= 2),
    Rule("INTERNAL_SPOOF", "flag", "Claims to be from the tenant's own domain but DMARC failed",
         lambda f: f["is_internal"] == 1 and f["dmarc_fail"] == 1),
    Rule("DISPLAY_NAME_MISMATCH", "flag", "Display name of an employee, sent from an outside address",
         lambda f: f["display_name_mismatch"] == 1),
    Rule("LOOKALIKE_DOMAIN", "block", "Sender domain imitates the tenant, a known vendor or a major brand",
         lambda f: f["lookalike_score"] >= 85),
    Rule("YOUNG_DOMAIN_HIGH_VOLUME", "block", "Domain under 30 days old sending 5+ emails in 24h",
         lambda f: f["sender_domain_age_days"] < 30 and f["domain_volume_24h"] >= 5),
    Rule("BAD_IP", "flag", "Sending IP is on a blocklist",
         lambda f: f["ip_score"] < 0.2),
    Rule("REPLY_TO_MISMATCH", "flag", "Replies would go to a different domain than the sender",
         lambda f: f["reply_to_mismatch"] == 1),
]


def run_rules(features: dict[str, float]) -> list[Rule]:
    """Rules that fire. NaN signals (service timeouts) compare False, so rules fail open."""
    return [r for r in RULES if r.fires(features)]


def blocks(hits: list[Rule], features: dict[str, float]) -> bool:
    """True if Tier 0 alone should quarantine: a block rule fired on a first-time sender."""
    return features["first_time_sender"] == 1 and any(r.severity == "block" for r in hits)
