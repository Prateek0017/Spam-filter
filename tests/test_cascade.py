"""Phase 4: cascade routing (tiers, gray zone, intent check, async scan) with stub models."""
from __future__ import annotations

import copy
import time
from collections import Counter
from datetime import datetime

import numpy as np
import pytest

from src.common.config import load_config
from src.data.generate import generate
from src.data.schema import Action, Attachment, AuthResults, Email, Url
from src.features.extract import FeatureExtractor, email_text, merge_stream
from src.models.text import make_vectorizer
from src.pipeline.cascade import Cascade
from src.services import build_services


class StubLGBM:
    def __init__(self, proba: list[float]) -> None:
        self.proba = np.array([proba])

    def predict_proba(self, X):  # type: ignore[no-untyped-def]
        return self.proba


class StubLR:
    def predict_proba(self, X):  # type: ignore[no-untyped-def]
        return np.array([[0.5, 0.5]])


class StubIntent:
    def __init__(self, **intents: float) -> None:
        self.intents = {"payment": 0.0, "gift_card": 0.0, "credential": 0.0, "urgency": 0.0,
                        "off_channel": 0.0} | intents

    def predict(self, X, texts):  # type: ignore[no-untyped-def]
        return [self.intents]


@pytest.fixture(scope="module")
def world():
    cfg = load_config()
    cfg["data"]["n_emails"] = 600
    tenants, emails, intel, _, sent = generate(cfg)
    return cfg, tenants, emails, intel, sent


def make_cascade(world, proba: list[float], cfg: dict | None = None, simulate_latency: bool = False,
                 **intents: float) -> Cascade:
    cfg0, tenants, emails, intel, sent = world
    cfg = cfg or cfg0
    vec = make_vectorizer().fit([email_text(e) for e in emails])
    fx = FeatureExtractor(tenants, build_services(cfg, intel=intel, simulate_latency=simulate_latency), vec)
    cas = Cascade(cfg, fx, {"vectorizer": vec, "lr": StubLR()}, StubLGBM(proba), StubIntent(**intents))
    for item in merge_stream(emails, sent):          # warm-up history: legit-labelled mail counts as delivered
        cas.observe(item, delivered=isinstance(item, Email) and item.category == "legit")
    return cas


def slow_cfg(world, p50_ms: float, timeout_ms: float, deadline_ms: float) -> dict:
    cfg = copy.deepcopy(world[0])
    for name in ("ip_reputation", "whois", "url_reputation"):
        cfg["services"][name] = {"p50_ms": p50_ms, "sigma": 0.0, "timeout_ms": timeout_ms}
    cfg["cascade"]["sync_deadline_ms"] = deadline_ms
    return cfg


def internal_email(world, **kw) -> Email:
    """An email from the colleague who has sent the most mail in tenant 0 (i.e. an established sender)."""
    _, tenants, emails, _, _ = world
    t = tenants[0]
    sender = Counter(e.from_addr for e in emails if e.from_addr in t.names).most_common(1)[0][0]
    last = [e for e in emails if e.from_addr == sender][-1]        # same style -> no topic shift
    return Email(message_id="<t@x>", tenant_id=t.tenant_id, to_addr=last.to_addr,   # an existing exchange
                 timestamp=datetime(2026, 8, 1, 10), from_addr=sender, from_display=t.names[sender],
                 subject=last.subject, body=last.body, **kw)


def test_confident_scores_decide_at_tier1(world) -> None:
    clean = make_cascade(world, [0.95, 0.01, 0.01, 0.02, 0.01]).classify(internal_email(world))
    assert (clean.action, clean.tier, clean.category) == (Action.DELIVER, 1, "legit")
    assert clean.latency_ms > 0
    spam = make_cascade(world, [0.05, 0.9, 0.02, 0.02, 0.01]).classify(internal_email(world))
    assert (spam.action, spam.tier) == (Action.SPAM_FOLDER, 1)
    bec = make_cascade(world, [0.05, 0.02, 0.02, 0.9, 0.01]).classify(internal_email(world))
    assert (bec.action, bec.category) == (Action.QUARANTINE, "bec") and "MODEL_HIGH_RISK" in bec.reasons


def test_gray_zone_intent_check(world) -> None:
    gray = [0.5, 0.05, 0.05, 0.35, 0.05]
    # Known internal colleague, asks for nothing risky -> deliver.
    v = make_cascade(world, gray).classify(internal_email(world))
    assert (v.action, v.tier) == (Action.DELIVER, 2)
    # Same colleague asks for a payment -> banner (asks, but the relationship looks normal).
    v = make_cascade(world, gray, payment=0.9).classify(internal_email(world))
    assert v.action == Action.WARNING_BANNER and "ASKS_PAYMENT" in v.reasons
    # Established colleague asks for payment AND something is off (reply-to elsewhere) -> banner, never quarantine.
    odd = internal_email(world).model_copy(update={"reply_to": "billing@elsewhere-pay.com"})
    v = make_cascade(world, gray, payment=0.9).classify(odd)
    assert v.action == Action.WARNING_BANNER and {"ASKS_PAYMENT", "ESTABLISHED_SENDER"} <= set(v.reasons)
    # Payment request from a first-time freemail sender -> quarantine.
    stranger = internal_email(world).model_copy(update={"from_addr": "ceo.office.1234@gmail.com"})
    v = make_cascade(world, gray, payment=0.9).classify(stranger)
    assert v.action == Action.QUARANTINE and {"ASKS_PAYMENT", "NEW_SENDER"} <= set(v.reasons)


def test_tier0_block_and_async_virus_scan(world) -> None:
    _, tenants, _, intel, _ = world
    t = tenants[0]
    lookalike = internal_email(world).model_copy(update={"from_addr": f"it@{t.domain.split('.')[0]}-secure.com"})
    v = make_cascade(world, [0.95, 0.01, 0.01, 0.02, 0.01]).classify(lookalike)
    assert (v.action, v.tier) == (Action.QUARANTINE, 0) and "LOOKALIKE_DOMAIN" in v.reasons

    intel.malware_hashes.add("badhash")
    infected = internal_email(world, attachments=[Attachment(filename="q3.xlsm", sha256="badhash")])
    v = make_cascade(world, [0.95, 0.01, 0.01, 0.02, 0.01]).classify(infected)
    assert v.action == Action.DELIVER                       # sync path does not wait for the scan
    v, scan_ms = Cascade.remediate(v, timeout_s=5)
    assert v.action == Action.QUARANTINE and "VIRUS_DETECTED" in v.reasons and scan_ms > 0


def test_intent_keyword_layer() -> None:
    from src.pipeline.intent import asks_for_money, asks_off_channel

    scam = "You are hired at tesla, pay 5000 dollar as resignation fee at +1 (415) 555-0172"
    assert asks_for_money(scam) and asks_off_channel(scam)
    assert asks_for_money("Rs 15,000 processing charge") and asks_for_money("a refundable deposit is required")
    assert asks_off_channel("message our HR manager on Telegram @hr_desk")
    # Identifiers and times are not phone numbers; ordinary requests are not money requests.
    for text in ("Invoice INV-40236 for PO-1234", "order 44017 on July 20th", "tracking US9514901185421",
                 "see you at 12:30 in room 4"):
        assert not asks_off_channel(text)
    assert not asks_for_money("Can you review the Q3 deck before Friday?")


def test_quarantined_mail_never_earns_trust(world) -> None:
    """Regression: a stranger's payment request is quarantined; observing it must not make the
    stranger 'established', so the second identical request is still quarantine-eligible."""
    gray = [0.5, 0.05, 0.05, 0.35, 0.05]
    cas = make_cascade(world, gray, payment=0.9)
    first = internal_email(world).model_copy(update={"from_addr": "ap.billing.desk@outlook.com",
                                                     "from_display": "Billing Desk"})
    v1 = cas.classify(first)
    assert v1.action == Action.QUARANTINE
    cas.observe(first, delivered=v1.action == Action.DELIVER)
    for _ in range(3):                                      # even repeated quarantined attempts earn nothing
        v2 = cas.classify(first.model_copy(update={"message_id": "<t2@x>"}))
        assert v2.action == Action.QUARANTINE and "ESTABLISHED_SENDER" not in v2.reasons
        cas.observe(first, delivered=v2.action == Action.DELIVER)


def test_slow_services_fail_open_to_deliver(world) -> None:
    """Lookups slower than the sync deadline: the verdict is DELIVER (fail open), decided at the deadline."""
    cfg = slow_cfg(world, p50_ms=400, timeout_ms=2000, deadline_ms=100)
    cas = make_cascade(world, [0.05, 0.02, 0.02, 0.9, 0.01], cfg=cfg, simulate_latency=True)
    v = cas.classify(internal_email(world))
    assert v.action == Action.DELIVER and v.tier == -1 and "DEADLINE_EXCEEDED" in v.reasons
    assert v.latency_ms < 300                              # did not wait for the 400 ms lookups


def test_many_urls_stay_under_the_deadline(world) -> None:
    """40 link domains = 82 lookups of 20 ms each: sequential would take ~1.6 s; in parallel it fits in 1 s."""
    cfg = slow_cfg(world, p50_ms=20, timeout_ms=100, deadline_ms=1000)
    cas = make_cascade(world, [0.95, 0.01, 0.01, 0.02, 0.01], cfg=cfg, simulate_latency=True)
    urls = [Url(href=f"https://site{i}.example-{i}.com/x", anchor_text="x") for i in range(40)]
    v = cas.classify(internal_email(world, urls=urls))
    assert v.tier != -1 and v.latency_ms < 1000


def test_spoofed_sender_inherits_no_trust(world) -> None:
    """A message claiming to be from an established colleague but failing DMARC is treated as a stranger."""
    gray = [0.5, 0.05, 0.05, 0.35, 0.05]
    cas = make_cascade(world, gray, payment=0.9)
    real = internal_email(world).model_copy(update={"reply_to": "billing@elsewhere-pay.com"})
    assert cas.classify(real).action == Action.WARNING_BANNER          # genuine colleague: banner only
    spoof = real.model_copy(update={"auth": AuthResults(spf="fail", dkim="none", dmarc="fail")})
    v = cas.classify(spoof)
    assert v.action == Action.QUARANTINE and "ESTABLISHED_SENDER" not in v.reasons


def test_quarantined_lookalike_keeps_tier0_block(world) -> None:
    """Regression: a quarantined lookalike sender that tries again is still blocked at Tier 0."""
    _, tenants, _, _, _ = world
    cas = make_cascade(world, [0.95, 0.01, 0.01, 0.02, 0.01])
    lookalike = internal_email(world).model_copy(
        update={"from_addr": f"it@{tenants[0].domain.split('.')[0]}-secure.com", "from_display": "IT"})
    for attempt in range(3):
        v = cas.classify(lookalike.model_copy(update={"message_id": f"<l{attempt}@x>"}))
        assert (v.action, v.tier) == (Action.QUARANTINE, 0), attempt
        cas.observe(lookalike, delivered=v.action == Action.DELIVER)


def test_one_clean_delivery_does_not_establish(world) -> None:
    """Regression: one benign delivered email does not make a stranger established (3 are needed)."""
    gray = [0.5, 0.05, 0.05, 0.35, 0.05]
    cas = make_cascade(world, gray, payment=0.9)
    stranger = internal_email(world).model_copy(update={"from_addr": "j.doe.consulting@outlook.com",
                                                        "from_display": "J Doe"})
    cas.observe(stranger, delivered=True)                  # one benign email reached the inbox
    v = cas.classify(stranger.model_copy(update={"message_id": "<pay@x>"}))
    assert v.action == Action.QUARANTINE and "NEW_SENDER" in v.reasons
    assert "ESTABLISHED_SENDER" not in v.reasons


def test_dmarc_failing_deliveries_earn_no_trust(world) -> None:
    """Regression: three delivered emails that failed DMARC leave the sender not established."""
    cas = make_cascade(world, [0.5, 0.05, 0.05, 0.35, 0.05], payment=0.9)
    fail = AuthResults(spf="fail", dkim="none", dmarc="fail")
    sender = internal_email(world).model_copy(update={"from_addr": "accounts@partner-billing.com",
                                                      "from_display": "Accounts", "auth": fail})
    for i in range(3):
        cas.observe(sender.model_copy(update={"message_id": f"<d{i}@x>"}), delivered=True)
    passing = sender.model_copy(update={"auth": AuthResults(), "message_id": "<p@x>"})
    assert not cas.fx.is_established(passing)
    assert cas.classify(passing).action == Action.QUARANTINE


class SlowLGBM(StubLGBM):
    def predict_proba(self, X):  # type: ignore[no-untyped-def]
        time.sleep(1.0)
        return self.proba


def test_slow_model_returns_deliver_at_the_deadline(world) -> None:
    """A model that takes 1 s cannot hold the provider past a 200 ms deadline: DELIVER, on time."""
    cfg = copy.deepcopy(world[0])
    cfg["cascade"]["sync_deadline_ms"] = 200
    cas = make_cascade(world, [0.05, 0.02, 0.02, 0.9, 0.01], cfg=cfg)
    cas.lgbm = SlowLGBM([0.05, 0.02, 0.02, 0.9, 0.01])
    t0 = time.perf_counter()
    v = cas.classify(internal_email(world))
    elapsed = (time.perf_counter() - t0) * 1000
    assert v.action == Action.DELIVER and v.tier == -1 and "DEADLINE_EXCEEDED" in v.reasons
    assert elapsed < 400                                  # returned at the deadline, not after the model
