"""Point-in-time feature extraction.

`FeatureExtractor` walks the stream in timestamp order: `extract(email)` only reads state
built by earlier `update()` calls, so no feature can see the future. The same object (with
its accumulated history) is saved after training and reused by the cascade and the demo.

`text_score` is not computed here: it comes from the TF-IDF + LR text model and is added
by the training script (out-of-fold on train) and by the cascade at inference time.
"""
from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Any

import numpy as np
from rapidfuzz import fuzz
from scipy.sparse import csr_matrix
from sklearn.feature_extraction.text import TfidfVectorizer

from src.common.domains import BRAND_DOMAINS, URL_SHORTENERS, address_domain, is_freemail, registrable_domain, url_host
from src.data.schema import Email, Tenant
from src.services import Services
from src.services.virus_scan import MACRO_EXTENSIONS, RISKY_EXTENSIONS

FEATURES: list[str] = [
    # authentication / sender identity
    "auth_fail_count", "dmarc_fail", "is_internal", "is_freemail", "sender_domain_age_days",
    "lookalike_score", "display_name_mismatch", "reply_to_mismatch",
    # infrastructure
    "ip_score", "ip_geo_risk",
    # relationship history (point-in-time)
    "first_time_sender", "sender_prior_msgs", "prior_exchanges", "domain_volume_24h", "topic_shift",
    # content: URLs and attachments
    "n_urls", "url_bad_verdict", "min_url_domain_age_days", "anchor_mismatch", "offdomain_urls",
    "risky_attachments",
    # content: keywords + text model
    "urgency_kw", "payment_kw", "credential_kw", "text_score",
]

KEYWORDS: dict[str, re.Pattern[str]] = {
    "urgency_kw": re.compile(r"\b(urgent(ly)?|immediately|today|asap|within 24 hours|expires?|act now|overdue|"
                             r"confidential)\b"),
    "payment_kw": re.compile(r"\b(wire|payment|invoice|bank|remit|transfer|gift cards?|routing|beneficiary|"
                             r"direct deposit|paycheck)\b"),
    "credential_kw": re.compile(r"\b(password|verify|sign in|log ?in|credentials|confirm|account)\b"),
}
ARCHIVE_EXTENSIONS = frozenset({"zip", "rar", "7z", "iso", "img", "htm", "html"})
VOLUME_WINDOW = timedelta(hours=24)


URL_RE = re.compile(r"\S+://\S+")


def email_text(e: Email) -> str:
    """Subject + body with URLs and names masked.

    The text model should judge what an email *says*. Links are judged by the URL features and
    identity by the sender features; leaving them in lets the text model memorise signatures
    ("Acme Ltd", "IT Service Desk") instead of learning language.
    """
    text = URL_RE.sub(" URL ", f"{e.subject}\n{e.body}")
    first_name = re.split(r"[._\-+\d]+", e.to_addr.split("@")[0])[0]
    names = [n for n in (e.from_display.strip(), first_name) if len(n) >= 2]   # whole names only
    if names:
        text = re.sub(r"(?<!\w)(" + "|".join(map(re.escape, names)) + r")(?!\w)", " ", text, flags=re.I)
    return text


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
    def __init__(self, tenants: list[Tenant], services: Services, vectorizer: TfidfVectorizer) -> None:
        self.tenants = {t.tenant_id: t for t in tenants}
        self.protected = {t.tenant_id: {t.domain, *t.vendors, *BRAND_DOMAINS} for t in tenants}
        self.employee_names = {t.tenant_id: {n.lower() for n in t.names.values()} for t in tenants}
        self.services = services
        self.vectorizer = vectorizer
        # History state
        self.sender_msgs: Counter[tuple[str, str]] = Counter()           # (tenant, sender) -> #msgs
        self.pair_msgs: Counter[tuple[str, str]] = Counter()             # (mailbox, sender) -> #msgs
        self.domain_times: dict[str, list[datetime]] = defaultdict(list)  # sender domain -> timestamps
        self.sender_text: dict[tuple[str, str], csr_matrix] = {}         # (tenant, sender) -> sum of tf-idf

    def __getstate__(self) -> dict[str, Any]:
        state = self.__dict__.copy()
        state["services"] = None            # thread pools don't pickle; reattach with .services = ...
        return state

    # ---- extraction ----------------------------------------------------------------------
    def extract(self, e: Email, x_text: csr_matrix | None = None) -> tuple[dict[str, float], float]:
        """Return (features, service latency in ms). Lookups fan out in parallel, so latency = max."""
        svc, tenant = self.services, self.tenants[e.tenant_id]
        sender = e.from_addr.lower()
        dom = registrable_domain(address_domain(sender))
        key = (e.tenant_id, sender)
        f: dict[str, float] = {}
        latencies: list[float] = []

        auth = [e.auth.spf, e.auth.dkim, e.auth.dmarc]
        f["auth_fail_count"] = sum(a != "pass" for a in auth)
        f["dmarc_fail"] = float(e.auth.dmarc == "fail")
        f["is_internal"] = float(dom == tenant.domain)
        f["is_freemail"] = float(is_freemail(dom))
        who = svc.whois.lookup(dom, as_of=e.timestamp)
        latencies.append(who.latency_ms)
        f["sender_domain_age_days"] = who.value.age_days if who.value else np.nan
        f["lookalike_score"] = lookalike_score(dom, self.protected[e.tenant_id])
        f["display_name_mismatch"] = float(e.from_display.strip().lower() in self.employee_names[e.tenant_id]
                                           and dom != tenant.domain)
        f["reply_to_mismatch"] = float(bool(e.reply_to)
                                       and registrable_domain(address_domain(e.reply_to or "")) != dom)

        ip = svc.ip.lookup(e.sender_ip)
        latencies.append(ip.latency_ms)
        f["ip_score"] = ip.value.score if ip.value else np.nan
        f["ip_geo_risk"] = ip.value.geo_risk if ip.value else np.nan

        f["first_time_sender"] = float(self.sender_msgs[key] == 0)
        f["sender_prior_msgs"] = math.log1p(self.sender_msgs[key])
        replies_in_thread = sum(m.from_addr.lower() == e.to_addr.lower() for m in e.thread)
        f["prior_exchanges"] = math.log1p(self.pair_msgs[(e.to_addr, sender)] + replies_in_thread)
        f["domain_volume_24h"] = sum(1 for t in self.domain_times.get(dom, ())
                                     if e.timestamp - VOLUME_WINDOW <= t < e.timestamp)
        f["topic_shift"] = self._topic_shift(key, x_text if x_text is not None else self._vec(e))

        url_doms = sorted({registrable_domain(url_host(u.href)) for u in e.urls})
        bad, ages = 0.0, []
        for d in url_doms:
            r = svc.url.lookup(d)
            w = svc.whois.lookup(d, as_of=e.timestamp)
            latencies += [r.latency_ms, w.latency_ms]
            if r.value and r.value.verdict in ("malicious", "suspicious"):
                bad = max(bad, 1.0 if r.value.verdict == "malicious" else 0.5)
            if r.value and r.value.is_shortener:
                bad = max(bad, 0.5)
            if w.value and d not in URL_SHORTENERS:
                ages.append(w.value.age_days)
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

        text = email_text(e).lower()
        for name, pat in KEYWORDS.items():
            f[name] = float(len(pat.findall(text)))
        return f, max(latencies)

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
    def update(self, e: Email, x_text: csr_matrix | None = None) -> None:
        sender = e.from_addr.lower()
        key = (e.tenant_id, sender)
        self.sender_msgs[key] += 1
        self.pair_msgs[(e.to_addr, sender)] += 1
        times = self.domain_times[registrable_domain(address_domain(sender))]
        times.append(e.timestamp)
        while times and e.timestamp - times[0] > VOLUME_WINDOW:    # stream is time ordered
            times.pop(0)
        x = x_text if x_text is not None else self._vec(e)
        self.sender_text[key] = x if key not in self.sender_text else self.sender_text[key] + x
