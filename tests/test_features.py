"""Phase 3: features are point-in-time, and the Tier 0 rules behave as documented."""
from __future__ import annotations

import math
from datetime import datetime

import numpy as np
import pytest

from src.common.config import load_config
from src.data.generate import generate
from src.data.schema import Email, SentMessage, ThreadMessage
from src.features.extract import FEATURES, FeatureExtractor, email_text, lookalike_score, merge_stream
from src.models.text import make_vectorizer
from src.rules.engine import blocks, run_rules
from src.services import build_services


@pytest.fixture(scope="module")
def stream():
    cfg = load_config()
    cfg["data"]["n_emails"] = 1500
    tenants, emails, intel, _, sent = generate(cfg)
    vec = make_vectorizer().fit([email_text(e) for e in emails[:800]])
    return cfg, tenants, emails, intel, vec, sent


def _extractor(stream) -> FeatureExtractor:
    cfg, tenants, _, intel, vec, _ = stream
    return FeatureExtractor(tenants, build_services(cfg, intel=intel), vec)


def _walk(stream, n: int) -> list[dict[str, float]]:
    """Replay inbound mail + sent-mail log in time order; features of the first n emails."""
    _, _, emails, _, _, sent = stream
    fx, out = _extractor(stream), []
    for item in merge_stream(emails, sent):
        if isinstance(item, SentMessage):
            fx.record_sent(item)
            continue
        if len(out) == n:
            break
        out.append(fx.extract(item)[0])
        fx.update(item)
    return out


def _same(a: float, b: float) -> bool:
    return (math.isnan(a) and math.isnan(b)) or a == b


def test_features_ignore_future_emails(stream) -> None:
    """Features of the first 400 emails are identical whether or not 1100 later emails exist."""
    short, full = _walk(stream, 400), _walk(stream, 1500)[:400]
    for a, b in zip(short, full):
        assert all(_same(a[k], b[k]) for k in a)


def test_history_starts_empty_and_grows(stream) -> None:
    _, _, emails, _, _, _ = stream
    feats = _walk(stream, 1500)
    seen: set[tuple[str, str]] = set()
    for e, f in zip(emails, feats):
        key = (e.tenant_id, e.from_addr.lower())
        assert math.isnan(f["topic_shift"]) == (key not in seen)
        seen.add(key)
    assert set(FEATURES) - {"text_score"} == set(feats[0])     # text_score is added by the trainer


def test_fake_reply_uses_history_not_the_quoted_thread(stream) -> None:
    _, tenants, emails, _, _, _ = stream
    t = tenants[0]
    to, stranger = t.mailboxes[3], "anna.k@new-partner-co.com"
    forged = [ThreadMessage(from_addr=to, timestamp=datetime(2026, 7, 1), subject="Q3 budget")]
    reply = Email(message_id="<r@x>", tenant_id=t.tenant_id, to_addr=to, timestamp=datetime(2026, 8, 1),
                  from_addr=stranger, subject="RE: Q3 budget", body="Please see the updated budget.", thread=forged)
    fx = _extractor(stream)
    assert fx.extract(reply)[0]["fake_reply"] == 1                # forged quote does not count
    fx.record_sent(SentMessage(tenant_id=t.tenant_id, from_addr=to, to_addr=stranger,
                               timestamp=datetime(2026, 7, 1), subject="Q3 budget"))
    f = fx.extract(reply)[0]
    assert f["fake_reply"] == 0 and f["prior_exchanges"] > 0        # a real earlier exchange does
    shouty = reply.model_copy(update={"subject": "URGENT!!! 💰 Payment today"})
    s = fx.extract(shouty)[0]
    assert s["subject_caps_ratio"] > 0.3 and s["subject_exclaims"] == 3 and s["subject_emojis"] == 1
    assert s["subject_kw"] == 3 and s["fake_reply"] == 0


def test_lookalike_score() -> None:
    protected = {"paypal.com", "acmesupply.com", "ledgerly.io"}
    assert lookalike_score("paypal.com", protected) == 0          # the real domain is not a lookalike
    assert lookalike_score("paypa1.com", protected) >= 85         # homoglyph
    assert lookalike_score("ledgerly-secure.io", protected) == 100  # brand + hyphen keyword
    assert lookalike_score("acmesupply.net", protected) == 100      # TLD swap
    assert lookalike_score("brightcart.com", protected) < 85


def test_rules_block_only_unestablished_senders_and_fail_open() -> None:
    base = {k: 0.0 for k in FEATURES} | {"sender_domain_age_days": 3000, "ip_score": 0.9}
    lookalike = base | {"lookalike_score": 95.0}
    hits = run_rules(lookalike)
    assert [r.code for r in hits] == ["LOOKALIKE_DOMAIN"] and blocks(hits, established=False)
    assert not blocks(hits, established=True)                     # e.g. a sister company we talk to
    timed_out = base | {"ip_score": np.nan, "sender_domain_age_days": np.nan, "domain_volume_24h": 50}
    assert run_rules(timed_out) == []                             # missing signals never fire a rule
    loud_subject = base | {"fake_reply": 1.0, "subject_body_sim": 0.0, "subject_kw": 5.0,
                           "subject_caps_ratio": 1.0, "subject_exclaims": 5.0, "subject_emojis": 3.0}
    assert run_rules(loud_subject) == []                          # the subject alone never fires a rule
