"""The decision cascade: rules -> LightGBM -> intent check, with the virus scan alongside.

  Deadline  the provider waits at most `sync_deadline_ms`. The whole decision (lookups, rules, models)
          runs in a worker under a hard timeout; lookups also run concurrently, each with its own
          timeout. If the deadline passes, classify() returns DELIVER (fail open) at the deadline and
          only the async path can still pull the email.
  Tier 0  signals + rules. A block rule on a sender who is not established quarantines immediately, before any
          model runs.
  Tier 1  text score + LightGBM. Confident scores (outside the gray zone) decide here.
  Tier 2  gray zone only: does the email ask for money, gift cards or credentials, and is
          something off about the relationship (new sender, topic shift, mismatched
          reply-to / display name, freemail)? Both -> quarantine, one -> banner, neither -> deliver.
          An established correspondent is never quarantined here, only bannered: Tier 2 signals
          are soft, and a real vendor's payment request must still reach the user. "Established" has
          one definition, FeatureExtractor.is_established, used by Tier 0, the model and Tier 2.
  Async   attachments go to the virus scanner the moment the email arrives. The scan is slow
          (median ~2.5s) so the cascade never waits; an infected verdict pulls the email
          from the mailbox after delivery (`remediate`).
"""
from __future__ import annotations

import json
import time
from concurrent.futures import Future, ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
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
    score: float                      # P(malicious) from LightGBM (NaN when the model did not run)
    tier: int                         # tier that made the decision (-1 = deadline expired, fail open)
    reasons: list[str]
    latency_ms: float                 # wall time of the synchronous path
    cpu_ms: float = 0.0               # CPU time spent (for the cost estimate)
    features: dict[str, float] = field(default_factory=dict)
    intents: dict[str, float] = field(default_factory=dict)
    scans: list[Future] = field(default_factory=list, repr=False)


def rule_category(f: dict[str, float], hits: list) -> str:
    """Class label for a Tier 0 block, decided without the model: attachment -> malware, link ->
    phishing, bulk from a young domain -> spam, otherwise an impersonation with no payload -> BEC."""
    if f["risky_attachments"] > 0:
        return "malware"
    if f["n_urls"] > 0:
        return "phishing"
    if any(h.code == "YOUNG_DOMAIN_HIGH_VOLUME" for h in hits) and f["lookalike_score"] < 85:
        return "spam"
    return "bec"


class Cascade:
    def __init__(self, cfg: dict[str, Any], extractor: FeatureExtractor, text_model: dict, lgbm: Any,
                 intent_model: Any, fill: dict[str, float] | None = None) -> None:
        c = cfg["cascade"]
        self.lo, self.hi = c["gray_zone"]
        self.topic_shift_hi = c["topic_shift_high"]
        self.intent_min = c["intent_min"]
        self.deadline_s = c["sync_deadline_ms"] / 1000
        self.fx, self.vec, self.text_lr = extractor, text_model["vectorizer"], text_model["lr"]
        self.lgbm, self.intent = lgbm, intent_model
        self.fill = fill or {}                         # typical (median) values for missing model inputs

    @classmethod
    def load(cls, cfg: dict[str, Any], fresh_history: bool = False, simulate_latency: bool = False,
             simulate_scan_latency: bool | None = None) -> "Cascade":
        """Load saved models. fresh_history=True starts with empty sender history (for replaying a stream)."""
        m = Path(cfg["paths"]["models"])
        text_model = joblib.load(m / "text_model.joblib")
        services = build_services(cfg, simulate_latency=simulate_latency, simulate_scan_latency=simulate_scan_latency)
        if fresh_history:
            fx = FeatureExtractor(load_tenants(Path(cfg["paths"]["raw"]) / "tenants.json"), services,
                                  text_model["vectorizer"], cfg["cascade"]["established_min_msgs"])
        else:
            fx = joblib.load(m / "feature_extractor.joblib")
            fx.services = services
        return cls(cfg, fx, text_model, joblib.load(m / "lgbm.joblib"), joblib.load(m / "intent.joblib"),
                   json.loads((m / "feature_fill.json").read_text()))

    def observe(self, item: Email | SentMessage, delivered: bool = False) -> None:
        """Add a received email (delivered=True only if it reached the inbox without a banner and was
        not pulled later) or a message the mailbox sent to relationship history."""
        if isinstance(item, SentMessage):
            self.fx.record_sent(item)
        else:
            self.fx.update(item, self.vec.transform([email_text(item)]), delivered=delivered)

    def _runner(self) -> ThreadPoolExecutor:
        if getattr(self, "_pool", None) is None:
            self._pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="classify")
        return self._pool

    def classify(self, email: Email) -> Verdict:
        """Decide under a hard deadline: if the decision is not ready by `sync_deadline_ms`, return DELIVER
        (fail open) at the deadline; the late result is discarded and the async scan can still pull."""
        t0, cpu0 = time.perf_counter(), time.process_time()
        deadline = t0 + self.deadline_s
        scans = [self.fx.services.virus.submit(a) for a in email.attachments]   # runs alongside
        future = self._runner().submit(self._decide, email, deadline)
        try:
            action, cat, score, tier, reasons, feats, intents = future.result(
                timeout=max(0.0, deadline - time.perf_counter()))
        except FutureTimeout:
            action, cat, score, tier, reasons, feats, intents = (
                Action.DELIVER, "legit", float("nan"), -1, ["DEADLINE_EXCEEDED"], {}, {})
        if tier != -1 and time.perf_counter() > deadline:        # finished, but after the deadline
            action, cat, tier, reasons = Action.DELIVER, "legit", -1, reasons + ["DEADLINE_EXCEEDED"]
        return Verdict(action, cat, score, tier, list(dict.fromkeys(reasons)),
                       (time.perf_counter() - t0) * 1000, (time.process_time() - cpu0) * 1000,
                       feats, intents, scans)

    def _decide(self, email: Email, deadline: float) -> tuple:
        """Lookups, rules, models and the intent check. Returns (action, category, score, tier,
        reasons, features, intents)."""
        text = email_text(email)
        x = self.vec.transform([text])
        feats, expired = self.fx.extract(email, x, deadline=deadline)
        if expired:
            return Action.DELIVER, "legit", float("nan"), -1, ["DEADLINE_EXCEEDED"], feats, {}
        established = self.fx.is_established(email)             # the one shared trust definition
        hits = run_rules(feats)
        reasons = [r.code for r in hits]
        if blocks(hits, established):                            # Tier 0: decided before any model runs
            return Action.QUARANTINE, rule_category(feats, hits), float("nan"), 0, reasons, feats, {}

        feats["text_score"] = float(self.text_lr.predict_proba(x)[0, 1])
        proba = self.lgbm.predict_proba(model_input([feats], self.fill))[0]
        score = float(1 - proba[0])
        mal_cat = CATEGORIES[1 + int(np.argmax(proba[1:]))]
        bad_action = Action.SPAM_FOLDER if mal_cat == "spam" else Action.QUARANTINE
        intents: dict[str, float] = {}

        if score < self.lo:
            tier, action, cat = 1, Action.DELIVER, "legit"
        elif score >= self.hi:
            tier, action, cat = 1, bad_action, mal_cat
            reasons.append("MODEL_HIGH_RISK")
        else:
            tier, cat = 2, mal_cat
            intents = self.intent.predict(x, [text])[0]
            asks = [i for i in RISKY_INTENTS if intents[i] >= self.intent_min]
            off = self._relationship_flags(feats, established)
            reasons += [f"ASKS_{i.upper()}" for i in asks] + off
            if asks and off and established:
                action = Action.WARNING_BANNER
                reasons.append("ESTABLISHED_SENDER")
            elif asks and off:
                action = Action.QUARANTINE
            elif asks or off:
                action = Action.SPAM_FOLDER if mal_cat == "spam" and not asks else Action.WARNING_BANNER
            else:
                action, cat = Action.DELIVER, "legit"
        return action, cat, score, tier, reasons, feats, intents

    def _relationship_flags(self, f: dict[str, float], established: bool) -> list[str]:
        flags = []
        untrusted = not established
        if untrusted:
            flags.append("NEW_SENDER")
        if f["topic_shift"] >= self.topic_shift_hi:          # NaN (no history) compares False
            flags.append("TOPIC_SHIFT")
        if f["reply_to_mismatch"] == 1:
            flags.append("REPLY_TO_MISMATCH")
        if f["display_name_mismatch"] == 1:
            flags.append("DISPLAY_NAME_MISMATCH")
        if f["is_freemail"] == 1 and untrusted:
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
