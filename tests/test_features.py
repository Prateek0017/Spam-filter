"""Phase 3: features are point-in-time, and the Tier 0 rules behave as documented."""
from __future__ import annotations

import math

import numpy as np
import pytest

from src.common.config import load_config
from src.data.generate import generate
from src.features.extract import FEATURES, FeatureExtractor, email_text, lookalike_score
from src.models.text import make_vectorizer
from src.rules.engine import blocks, run_rules
from src.services import build_services


@pytest.fixture(scope="module")
def stream():
    cfg = load_config()
    cfg["data"]["n_emails"] = 1500
    tenants, emails, intel, _ = generate(cfg)
    vec = make_vectorizer().fit([email_text(e) for e in emails[:800]])
    return cfg, tenants, emails, intel, vec


def _walk(stream, n: int) -> list[dict[str, float]]:
    cfg, tenants, emails, intel, vec = stream
    fx = FeatureExtractor(tenants, build_services(cfg, intel=intel), vec)
    out = []
    for e in emails[:n]:
        out.append(fx.extract(e)[0])
        fx.update(e)
    return out


def _same(a: float, b: float) -> bool:
    return (math.isnan(a) and math.isnan(b)) or a == b


def test_features_ignore_future_emails(stream) -> None:
    """Features of the first 400 emails are identical whether or not 1100 later emails exist."""
    short, full = _walk(stream, 400), _walk(stream, 1500)[:400]
    for a, b in zip(short, full):
        assert all(_same(a[k], b[k]) for k in a)


def test_history_starts_empty_and_grows(stream) -> None:
    _, _, emails, _, _ = stream
    feats = _walk(stream, 1500)
    seen: set[tuple[str, str]] = set()
    for e, f in zip(emails, feats):
        key = (e.tenant_id, e.from_addr.lower())
        assert f["first_time_sender"] == float(key not in seen)
        assert math.isnan(f["topic_shift"]) == (key not in seen)
        seen.add(key)
    assert set(FEATURES) - {"text_score"} == set(feats[0])     # text_score is added by the trainer


def test_lookalike_score() -> None:
    protected = {"paypal.com", "acmesupply.com", "ledgerly.io"}
    assert lookalike_score("paypal.com", protected) == 0          # the real domain is not a lookalike
    assert lookalike_score("paypa1.com", protected) >= 85         # homoglyph
    assert lookalike_score("ledgerly-secure.io", protected) == 100  # brand + hyphen keyword
    assert lookalike_score("acmesupply.net", protected) == 100      # TLD swap
    assert lookalike_score("brightcart.com", protected) < 85


def test_rules_block_only_first_time_senders_and_fail_open() -> None:
    base = {k: 0.0 for k in FEATURES} | {"sender_domain_age_days": 3000, "ip_score": 0.9}
    lookalike = base | {"lookalike_score": 95.0, "first_time_sender": 1.0}
    hits = run_rules(lookalike)
    assert [r.code for r in hits] == ["LOOKALIKE_DOMAIN"] and blocks(hits, lookalike)
    known = lookalike | {"first_time_sender": 0.0}                # e.g. a sister company we talk to
    assert not blocks(run_rules(known), known)
    timed_out = base | {"ip_score": np.nan, "sender_domain_age_days": np.nan, "domain_volume_24h": 50}
    assert run_rules(timed_out) == []                             # missing signals never fire a rule
