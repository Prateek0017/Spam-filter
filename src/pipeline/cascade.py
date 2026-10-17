"""The decision cascade: rules -> LightGBM -> intent check, with the virus scan alongside.

  Tier 0  signals + rules. A block rule on a first-time sender quarantines immediately.
  Tier 1  text score + LightGBM. Confident scores (outside the gray zone) decide here.
  Tier 2  gray zone only: does the email ask for money, gift cards or credentials, and is
          something off about the relationship (new sender, topic shift, mismatched
          reply-to / display name, freemail)? Both -> quarantine, one -> banner, neither -> deliver.
          An established correspondent is never quarantined here, only bannered: Tier 2 signals
          are soft, and a real vendor's payment request must still reach the user.
  Async   attachments go to the virus scanner the moment the email arrives. The scan is slow
          (median ~2.5s) so the cascade never waits; an infected verdict pulls the email
          from the mailbox after delivery (`remediate`).
"""
from __future__ import annotations

import json
import math
import time
from concurrent.futures import Future
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from src.data.io import load_tenants
from src.data.schema import CATEGORIES, Action, Email, SentMessage
from src.features.extract import FeatureExtractor, email_text, model_input
from src.pipeline.intent import RISKY_INTENTS
from src.rules.engine import blocks, run_rules
from src.services import ServiceResult, build_services
from src.services.virus_scan import ScanVerdict


@dataclass
class Verdict:
    action: Action
    category: str                     # predicted category ("legit" when delivered clean)
    score: float                      # P(malicious) from LightGBM
    tier: int                         # tier that made the decision
    reasons: list[str]
    latency_ms: float                 # compute + external lookups (lookups fan out in parallel)
    features: dict[str, float] = field(default_factory=dict)
    intents: dict[str, float] = field(default_factory=dict)
    scans: list[Future] = field(default_factory=list, repr=False)


class Cascade:
    def __init__(self, cfg: dict[str, Any], extractor: FeatureExtractor, text_model: dict, lgbm: Any,
                 intent_model: Any, fill: dict[str, float] | None = None) -> None:
        c = cfg["cascade"]
        self.lo, self.hi = c["gray_zone"]
        self.topic_shift_hi = c["topic_shift_high"]
        self.intent_min = c["intent_min"]
        self.established_min_msgs = c["established_min_msgs"]
        self.fx, self.vec, self.text_lr = extractor, text_model["vectorizer"], text_model["lr"]
        self.lgbm, self.intent = lgbm, intent_model
        self.fill = fill or {}                         # neutral values for missing model inputs

    @classmethod
    def load(cls, cfg: dict[str, Any], fresh_history: bool = False, simulate_latency: bool = False) -> "Cascade":
        """Load saved models. fresh_history=True starts with empty sender history (for replaying a stream)."""
        m = Path(cfg["paths"]["models"])
        text_model = joblib.load(m / "text_model.joblib")
        services = build_services(cfg, simulate_latency=simulate_latency)
        if fresh_history:
            fx = FeatureExtractor(load_tenants(Path(cfg["paths"]["raw"]) / "tenants.json"), services,
                                  text_model["vectorizer"])
        else:
            fx = joblib.load(m / "feature_extractor.joblib")
            fx.services = services
        return cls(cfg, fx, text_model, joblib.load(m / "lgbm.joblib"), joblib.load(m / "intent.joblib"),
                   json.loads((m / "feature_fill.json").read_text()))

    def observe(self, item: Email | SentMessage) -> None:
        """Add a delivered email, or a message the mailbox sent, to relationship history."""
        if isinstance(item, SentMessage):
            self.fx.record_sent(item)
        else:
            self.fx.update(item, self.vec.transform([email_text(item)]))

    def classify(self, email: Email) -> Verdict:
        t0 = time.perf_counter()
        scans = [self.fx.services.virus.submit(a) for a in email.attachments]   # runs alongside
        text = email_text(email)
        x = self.vec.transform([text])
        feats, svc_ms = self.fx.extract(email, x)
        hits = run_rules(feats)
        reasons = [r.code for r in hits]
        feats["text_score"] = float(self.text_lr.predict_proba(x)[0, 1])
        proba = self.lgbm.predict_proba(model_input([feats], self.fill))[0]
        score = float(1 - proba[0])
        mal_cat = CATEGORIES[1 + int(np.argmax(proba[1:]))]
        bad_action = Action.SPAM_FOLDER if mal_cat == "spam" else Action.QUARANTINE
        intents: dict[str, float] = {}

        if blocks(hits, feats):
            tier, action, cat = 0, Action.QUARANTINE, mal_cat
        elif score < self.lo:
            tier, action, cat = 1, Action.DELIVER, "legit"
        elif score >= self.hi:
            tier, action, cat = 1, bad_action, mal_cat
            reasons.append("MODEL_HIGH_RISK")
        else:
            tier, cat = 2, mal_cat
            intents = self.intent.predict(x, [text])[0]
            asks = [i for i in RISKY_INTENTS if intents[i] >= self.intent_min]
            off = self._relationship_flags(feats)
            reasons += [f"ASKS_{i.upper()}" for i in asks] + off
            if asks and off and self._established(feats):
                action = Action.WARNING_BANNER
                reasons.append("ESTABLISHED_SENDER")
            elif asks and off:
                action = Action.QUARANTINE
            elif asks or off:
                action = Action.SPAM_FOLDER if mal_cat == "spam" and not asks else Action.WARNING_BANNER
            else:
                action, cat = Action.DELIVER, "legit"
        reasons = list(dict.fromkeys(reasons))                 # a rule and a flag can share a code
        latency = (time.perf_counter() - t0) * 1000 + svc_ms
        return Verdict(action, cat, score, tier, reasons, latency, feats, intents, scans)

    def _established(self, f: dict[str, float]) -> bool:
        """This mailbox has exchanged mail with the sender, or the sender has written to the company often."""
        return f["prior_exchanges"] > 0 or f["sender_prior_msgs"] >= math.log1p(self.established_min_msgs)

    def _relationship_flags(self, f: dict[str, float]) -> list[str]:
        flags = []
        if f["first_time_sender"] == 1:
            flags.append("NEW_SENDER")
        if f["topic_shift"] >= self.topic_shift_hi:          # NaN (no history) compares False
            flags.append("TOPIC_SHIFT")
        if f["reply_to_mismatch"] == 1:
            flags.append("REPLY_TO_MISMATCH")
        if f["display_name_mismatch"] == 1:
            flags.append("DISPLAY_NAME_MISMATCH")
        if f["is_freemail"] == 1 and f["first_time_sender"] == 1:
            flags.append("FREEMAIL_SENDER")
        return list(dict.fromkeys(flags))

    @staticmethod
    def remediate(verdict: Verdict, timeout_s: float | None = None) -> tuple[Verdict, float | None]:
        """Wait for attachment scans; if any is infected, pull the email (post-delivery quarantine).

        Returns the (possibly updated) verdict and the scan latency in ms that triggered it.
        """
        results: list[ServiceResult[ScanVerdict]] = [f.result(timeout=timeout_s) for f in verdict.scans]
        infected = [r for r in results if r.value and r.value.infected]
        if not infected or verdict.action == Action.QUARANTINE:
            return verdict, None
        verdict.action, verdict.category = Action.QUARANTINE, "malware"
        verdict.reasons = verdict.reasons + ["VIRUS_DETECTED"]
        return verdict, max(r.latency_ms for r in infected)
