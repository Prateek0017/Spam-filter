"""Point-in-time feature extraction.

`FeatureExtractor` walks the stream in timestamp order: `extract(email)` only reads state
built by earlier `update()` calls, so no feature can see the future. The same object (with
its accumulated history) is saved after training and reused by the cascade and the demo.

Relationship history also includes the tenant's sent-mail log (`record_sent`): a reply is only
"real" if this mailbox and sender actually exchanged mail before. The quoted thread inside an
email is never trusted, because attackers forge it.

`text_score` is not computed here: it comes from the TF-IDF + LR text model and is added
by the training script (out-of-fold on train) and by the cascade at inference time.
"""
from __future__ import annotations

import math
import re
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime, timedelta
from typing import Any

import numpy as np
import pandas as pd
from rapidfuzz import fuzz
from scipy.sparse import csr_matrix
from sklearn.feature_extraction.text import TfidfVectorizer

from src.common.domains import BRAND_DOMAINS, URL_SHORTENERS, address_domain, is_freemail, registrable_domain, url_host
from src.data.schema import Email, SentMessage, Tenant
from src.services import Services
from src.services.virus_scan import MACRO_EXTENSIONS, RISKY_EXTENSIONS

FEATURES: list[str] = [
    # authentication / sender identity
    "auth_fail_count", "dmarc_fail", "is_internal", "is_freemail", "sender_domain_age_days",
    "lookalike_score", "display_name_mismatch", "reply_to_mismatch",
    # infrastructure
    "ip_score", "ip_geo_risk",
    # relationship history (point-in-time)
    "untrusted_sender", "sender_prior_msgs", "prior_exchanges", "domain_volume_24h", "topic_shift",
    # content: URLs and attachments
    "n_urls", "url_bad_verdict", "min_url_domain_age_days", "anchor_mismatch", "offdomain_urls",
    "risky_attachments",
    # content: body keywords + text model
    "urgency_kw", "payment_kw", "credential_kw", "text_score",
    # subject line
    "fake_reply", "subject_body_sim", "subject_kw", "subject_caps_ratio", "subject_exclaims", "subject_emojis",
]
SUBJECT_FEATURES = FEATURES[-6:]

KEYWORDS: dict[str, re.Pattern[str]] = {
    "urgency_kw": re.compile(r"\b(urgent(ly)?|immediately|today|asap|within 24 hours|expires?|act now|overdue|"
                             r"confidential)\b"),
    "payment_kw": re.compile(r"\b(wire|payment|invoice|bank|remit|transfer|gift cards?|routing|beneficiary|"
                             r"direct deposit|paycheck)\b"),
    "credential_kw": re.compile(r"\b(password|verify|sign in|log ?in|credentials|confirm|account)\b"),
}
SUBJECT_KW = re.compile(r"\b(urgent(ly)?|immediately|today|asap|action required|overdue|expires?|final notice|"
                        r"wire|payment|invoice|bank|remit|transfer|gift cards?|direct deposit|refund)\b")
REPLY_PREFIX = re.compile(r"^\s*((re|fwd?|aw|wg)\s*:\s*)+", re.I)
EMOJI = re.compile("[\U0001F300-\U0001FAFF\u2600-\u27BF]")
ARCHIVE_EXTENSIONS = frozenset({"zip", "rar", "7z", "iso", "img", "htm", "html"})
VOLUME_WINDOW = timedelta(hours=24)


URL_RE = re.compile(r"\S+://\S+")


def email_text(e: Email) -> str:
    """Subject + body with URLs and names masked.

    The text model should judge what an email *says*. Links are judged by the URL features and
    identity by the sender features; leaving them in lets the text model memorise signatures
    ("Acme Ltd", "IT Service Desk") instead of learning language.
    """
    return mask(f"{REPLY_PREFIX.sub('', e.subject)}\n{e.body}", e)   # reply prefix is fake_reply's job


def mask(text: str, e: Email) -> str:
    """Replace URLs with a token and drop the sender's display name and the recipient's first name."""
    text = URL_RE.sub(" URL ", text)
    first_name = re.split(r"[._\-+\d]+", e.to_addr.split("@")[0])[0]
    names = [n for n in (e.from_display.strip(), first_name) if len(n) >= 2]   # whole names only
    if names:
        text = re.sub(r"(?<!\w)(" + "|".join(map(re.escape, names)) + r")(?!\w)", " ", text, flags=re.I)
    return text


def model_input(rows: pd.DataFrame | list[dict[str, float]], fill: dict[str, float]) -> pd.DataFrame:
    """Model input: FEATURES in order, missing values replaced by training medians.

    A feature is missing when there is nothing to measure (no earlier mail for topic shift, no links)
    or a lookup timed out. Left as NaN, LightGBM learns that "missing" itself means attack, because
    new senders are mostly attackers in training. The median supplies a typical value instead (not a
    guaranteed neutral contribution); "new sender" is carried explicitly by untrusted_sender. Rules
    see the raw values (NaN never fires).
    """
    X = rows[FEATURES] if isinstance(rows, pd.DataFrame) else pd.DataFrame(rows, columns=FEATURES)
    return X.fillna(fill)


def lookalike_score(domain: str, protected: set[str]) -> float:
    """0-100 similarity to the closest protected domain; 0 if it *is* a protected domain."""
    if domain in protected:
        return 0.0
    name = domain.split(".", 1)[0]
    best = 0.0
    for p in protected:
        pname = p.split(".", 1)[0]
        if name == pname or name.startswith(pname + "-"):    # TLD swap / "acme-billing.com"
            return 100.0
        best = max(best, fuzz.ratio(domain, p))
    return best


class FeatureExtractor:
    def __init__(self, tenants: list[Tenant], services: Services, vectorizer: TfidfVectorizer,
                 established_min_msgs: int = 3) -> None:
        self.tenants = {t.tenant_id: t for t in tenants}
        self.protected = {t.tenant_id: {t.domain, *t.vendors, *BRAND_DOMAINS} for t in tenants}
        self.employee_names = {t.tenant_id: {n.lower() for n in t.names.values()} for t in tenants}
        self.services = services
        self.vectorizer = vectorizer
        self.established_min_msgs = established_min_msgs
        # History state
        self.sender_msgs: Counter[tuple[str, str]] = Counter()           # (tenant, sender) -> #msgs
        self.pair_msgs: Counter[tuple[str, str]] = Counter()             # (mailbox, sender) -> #msgs received
        self.sent_msgs: Counter[tuple[str, str]] = Counter()             # (mailbox, recipient) -> #msgs sent
        self.trusted_msgs: Counter[tuple[str, str]] = Counter()          # (tenant, sender) -> #msgs DELIVERED
        self.domain_times: dict[str, list[datetime]] = defaultdict(list)  # sender domain -> timestamps
        self.sender_text: dict[tuple[str, str], csr_matrix] = {}         # (tenant, sender) -> sum of tf-idf

    def __getstate__(self) -> dict[str, Any]:
        state = self.__dict__.copy()
        state["services"] = None            # thread pools don't pickle; reattach with .services = ...
        state["_executor"] = None
        return state

    def _pool(self) -> ThreadPoolExecutor:
        if getattr(self, "_executor", None) is None:
            self._executor = ThreadPoolExecutor(max_workers=32, thread_name_prefix="lookup")
        return self._executor

    def _lookups(self, e: Email, dom: str, url_doms: list[str],
                 deadline: float | None) -> tuple[dict[tuple[str, str], Any], bool]:
        """Run WHOIS / IP / URL lookups concurrently. Each mock call has its own timeout; all of them
        share the sync deadline (a perf_counter time). Returns (finished results, deadline hit)."""
        svc = self.services
        calls = {("whois", dom): lambda: svc.whois.lookup(dom, as_of=e.timestamp),
                 ("ip", e.sender_ip): lambda: svc.ip.lookup(e.sender_ip)}
        for d in url_doms:
            calls[("url", d)] = lambda d=d: svc.url.lookup(d)
            calls.setdefault(("whois", d), lambda d=d: svc.whois.lookup(d, as_of=e.timestamp))
        futures = {k: self._pool().submit(fn) for k, fn in calls.items()}
        timeout = None if deadline is None else max(0.0, deadline - time.perf_counter())
        done, pending = wait(futures.values(), timeout=timeout)
        for f in pending:
            f.cancel()
        return {k: f.result() for k, f in futures.items() if f in done}, bool(pending)

    # ---- extraction ----------------------------------------------------------------------
    def extract(self, e: Email, x_text: csr_matrix | None = None,
                deadline: float | None = None) -> tuple[dict[str, float], bool]:
        """Return (features, deadline hit). Lookups that did not finish count as missing (NaN)."""
        tenant = self.tenants[e.tenant_id]
        sender = e.from_addr.lower()
        dom = registrable_domain(address_domain(sender))
        key = (e.tenant_id, sender)
        f: dict[str, float] = {}
        url_doms = sorted({registrable_domain(url_host(u.href)) for u in e.urls})
        res, expired = self._lookups(e, dom, url_doms, deadline)
        value = lambda k: res[k].value if k in res else None  # noqa: E731

        auth = [e.auth.spf, e.auth.dkim, e.auth.dmarc]
        f["auth_fail_count"] = sum(a != "pass" for a in auth)
        f["dmarc_fail"] = float(e.auth.dmarc == "fail")
        f["is_internal"] = float(dom == tenant.domain)
        f["is_freemail"] = float(is_freemail(dom))
        who = value(("whois", dom))
        f["sender_domain_age_days"] = who.age_days if who else np.nan
        f["lookalike_score"] = lookalike_score(dom, self.protected[e.tenant_id])
        f["display_name_mismatch"] = float(e.from_display.strip().lower() in self.employee_names[e.tenant_id]
                                           and dom != tenant.domain)
        f["reply_to_mismatch"] = float(bool(e.reply_to)
                                       and registrable_domain(address_domain(e.reply_to or "")) != dom)

        ip = value(("ip", e.sender_ip))
        f["ip_score"] = ip.score if ip else np.nan
        f["ip_geo_risk"] = ip.geo_risk if ip else np.nan

        f["untrusted_sender"] = float(not self.is_established(e))
        f["sender_prior_msgs"] = math.log1p(self.sender_msgs[key])
        pair = (e.to_addr.lower(), sender)
        exchanges = self.pair_msgs[pair] + self.sent_msgs[pair]       # history store only, never e.thread
        f["prior_exchanges"] = math.log1p(exchanges)
        f["domain_volume_24h"] = sum(1 for t in self.domain_times.get(dom, ())
                                     if e.timestamp - VOLUME_WINDOW <= t < e.timestamp)
        f["topic_shift"] = self._topic_shift(key, x_text if x_text is not None else self._vec(e))

        bad, ages = 0.0, []
        for d in url_doms:
            r, w = value(("url", d)), value(("whois", d))
            if r and r.verdict in ("malicious", "suspicious"):
                bad = max(bad, 1.0 if r.verdict == "malicious" else 0.5)
            if r and r.is_shortener:
                bad = max(bad, 0.5)
            if w and d not in URL_SHORTENERS:
                ages.append(w.age_days)
        f["n_urls"] = len(e.urls)
        f["url_bad_verdict"] = bad
        f["min_url_domain_age_days"] = min(ages) if ages else np.nan
        f["anchor_mismatch"] = float(sum(
            1 for u in e.urls
            if "." in u.anchor_text and " " not in u.anchor_text.strip()
            and registrable_domain(url_host(u.anchor_text)) != registrable_domain(url_host(u.href))))
        f["offdomain_urls"] = float(sum(registrable_domain(url_host(u.href)) != dom for u in e.urls))

        exts = [a.filename.rsplit(".", 1)[-1].lower() for a in e.attachments]
        f["risky_attachments"] = float(sum(
            x in RISKY_EXTENSIONS | MACRO_EXTENSIONS | ARCHIVE_EXTENSIONS or a.has_macro
            for x, a in zip(exts, e.attachments)))

        body = mask(e.body, e).lower()
        for name, pat in KEYWORDS.items():
            f[name] = float(len(pat.findall(body)))
        f.update(self._subject_features(e, exchanges))
        return f, expired

    def _subject_features(self, e: Email, exchanges: int) -> dict[str, float]:
        """Subject-line signals. Features only: no rule ever acts on the subject alone."""
        is_reply = bool(REPLY_PREFIX.match(e.subject))
        subject = REPLY_PREFIX.sub("", e.subject).strip()
        letters = [c for c in subject if c.isalpha()]
        if subject and e.body.strip():
            xs, xb = self.vectorizer.transform([mask(subject, e), mask(e.body, e)])
            sim = float(xs.multiply(xb).sum())          # rows are L2-normalised -> cosine
        else:
            sim = np.nan
        return {
            # "RE:/FW:" with no earlier mail between this mailbox and this sender, in either direction
            "fake_reply": float(is_reply and exchanges == 0),
            "subject_body_sim": sim,
            "subject_kw": float(len(SUBJECT_KW.findall(subject.lower()))),
            "subject_caps_ratio": sum(c.isupper() for c in letters) / len(letters) if letters else 0.0,
            "subject_exclaims": float(subject.count("!")),
            "subject_emojis": float(len(EMOJI.findall(subject))),
        }

    def _vec(self, e: Email) -> csr_matrix:
        return self.vectorizer.transform([email_text(e)])

    def _topic_shift(self, key: tuple[str, str], x: csr_matrix) -> float:
        """1 - cosine(this email, centroid of the sender's earlier emails to this tenant); NaN if no history."""
        hist = self.sender_text.get(key)
        if hist is None:
            return np.nan
        norm = math.sqrt(hist.multiply(hist).sum())
        return 1.0 - float(x.multiply(hist).sum()) / norm if norm else np.nan

    # ---- history -------------------------------------------------------------------------
    def trust(self, e: Email) -> tuple[int, int]:
        """(messages this mailbox SENT to the sender, earlier messages from the sender that were DELIVERED)."""
        sender = e.from_addr.lower()
        return self.sent_msgs[(e.to_addr.lower(), sender)], self.trusted_msgs[(e.tenant_id, sender)]

    def is_established(self, e: Email) -> bool:
        """THE trust definition, shared by Tier 0 (block rules), the `untrusted_sender` model feature and
        Tier 2: this mailbox has written to the sender, or at least `established_min_msgs` earlier emails
        from the sender were delivered with no banner. A message failing DMARC is never established:
        its From address may be spoofed."""
        if e.auth.dmarc == "fail":
            return False
        sent, delivered = self.trust(e)
        return sent > 0 or delivered >= self.established_min_msgs

    def update(self, e: Email, x_text: csr_matrix | None = None, delivered: bool = False) -> None:
        """Add a received email to history. Only `delivered` mail (no banner, not quarantined, not
        spam-foldered, not pulled later) that passed DMARC earns trust; every received email still counts
        for volume and topic history."""
        sender = e.from_addr.lower()
        key = (e.tenant_id, sender)
        if delivered and e.auth.dmarc != "fail":
            self.trusted_msgs[key] += 1
        self.sender_msgs[key] += 1
        self.pair_msgs[(e.to_addr.lower(), sender)] += 1
        times = self.domain_times[registrable_domain(address_domain(sender))]
        times.append(e.timestamp)
        while times and e.timestamp - times[0] > VOLUME_WINDOW:    # stream is time ordered
            times.pop(0)
        x = x_text if x_text is not None else self._vec(e)
        self.sender_text[key] = x if key not in self.sender_text else self.sender_text[key] + x

    def record_sent(self, m: SentMessage) -> None:
        """A message the tenant mailbox sent (from the sent-mail log)."""
        self.sent_msgs[(m.from_addr.lower(), m.to_addr.lower())] += 1


def merge_stream(emails: list[Email], sent: list[SentMessage]) -> list[Email | SentMessage]:
    """Inbound emails and sent-mail log in time order (sent first on ties), for point-in-time replay."""
    return sorted([*sent, *emails], key=lambda x: (x.timestamp, isinstance(x, Email)))
