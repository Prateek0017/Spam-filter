"""Phase 4: cascade routing (tiers, gray zone, intent check, async scan) with stub models."""
from __future__ import annotations

from collections import Counter
from datetime import datetime

import numpy as np
import pytest

from src.common.config import load_config
from src.data.generate import generate
from src.data.schema import Action, Attachment, Email
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


def make_cascade(world, proba: list[float], **intents: float) -> Cascade:
    cfg, tenants, emails, intel, sent = world
    vec = make_vectorizer().fit([email_text(e) for e in emails])
    fx = FeatureExtractor(tenants, build_services(cfg, intel=intel), vec)
    cas = Cascade(cfg, fx, {"vectorizer": vec, "lr": StubLR()}, StubLGBM(proba), StubIntent(**intents))
    for item in merge_stream(emails, sent):
        cas.observe(item)
    return cas


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
