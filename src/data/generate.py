"""Synthetic multi-tenant email stream with labelled spam / phishing / BEC / malware.

World: 10 tenants (one per industry), 30 mailboxes each, a fixed set of vendors and partners
per tenant, plus attacker infrastructure. Legit mail flows between known correspondents;
attacks arrive in campaigns (spam is bulk, BEC is targeted). Everything the mocked services
know (domain ages, IP reputation, URL verdicts, malware hashes) is written to intel.json.

Usage: python -m src.data.generate --config configs/default.yaml
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from pathlib import Path

import numpy as np
from faker import Faker

from src.common.config import load_config, seed_everything
from src.common.domains import BRAND_DOMAINS, FREEMAIL_DOMAINS
from src.data import templates as T
from src.data.schema import Attachment, AuthResults, Email, Industry, Tenant, ThreadMessage, Url
from src.services.base import ThreatIntel

TENANT_SPECS = [
    ("Northwind Fabrication", "northwindfab.com", Industry.MANUFACTURING),
    ("Celadon Therapeutics", "celadontx.com", Industry.PHARMA),
    ("Ledgerly", "ledgerly.io", Industry.FINTECH),
    ("Brightcart", "brightcart.com", Industry.RETAIL),
    ("Hale & Morrow LLP", "halemorrow.com", Industry.LEGAL),
    ("Bluepeak Freight", "bluepeakfreight.com", Industry.LOGISTICS),
    ("Riverbend Health", "riverbendhealth.org", Industry.HEALTHCARE),
    ("Granite Ridge Builders", "graniteridgebuild.com", Industry.CONSTRUCTION),
    ("Orbitly", "orbitly.io", Industry.SAAS),
    ("Westbrook Academy", "westbrook.edu", Industry.EDUCATION),
]
ROLES = ["CEO", "CFO", "Controller", "AP", "HR", "IT"]          # first six mailboxes
VENDOR_SUFFIXES = ["supply", "industrial", "systems", "logistics", "partners", "group", "labs", "tech"]
BRAND_SENDERS = {"Microsoft 365": "microsoft.com", "Microsoft Security": "microsoft.com",
                 "Microsoft account team": "microsoft.com",
                 "DocuSign": "docusign.net", "PayPal": "paypal.com", "DHL Express": "dhl.com"}
LEGIT_EXTRA_DOMAINS = ["industryweekly.com", "saasmetrics.io", "live.com", "sharepoint.com"]
PROMO_DOMAIN = "saasmetrics.io"
# Share of campaigns whose text copies ordinary business mail (no scam phrasing at all), so only
# sender, relationship and infrastructure signals can tell them apart.
P_PLAIN = {"phishing": 0.6, "bec": 0.6, "malware": 0.5}
HOMOGLYPHS = {"o": "0", "l": "1", "i": "l", "m": "rn", "e": "3"}


@dataclass
class Contact:
    addr: str
    name: str
    domain: str
    vendor_name: str = ""


class World:
    def __init__(self, cfg: dict) -> None:
        dcfg = cfg["data"]
        self.rng = seed_everything(cfg["seed"])
        Faker.seed(cfg["seed"])
        self.fake = Faker("en_US")
        self.start = datetime.combine(date.fromisoformat(str(dcfg["start_date"])), datetime.min.time())
        self.days = dcfg["days"]
        self.intel = ThreatIntel()
        self.domain_ips: dict[str, list[str]] = {}
        self.tenants: list[Tenant] = []
        self.vendors: dict[str, list[Contact]] = {}    # tenant_id -> vendor contacts
        self.partners: dict[str, list[Contact]] = {}   # tenant_id -> other external contacts
        self._build(dcfg["n_tenants"], dcfg["mailboxes_per_tenant"])

    # ---- infrastructure -------------------------------------------------------------------
    def ip(self) -> str:
        r = self.rng
        return f"{r.choice([23, 34, 45, 52, 64, 81, 91, 104, 141, 185, 193, 212])}.{r.integers(0, 256)}." \
               f"{r.integers(0, 256)}.{r.integers(1, 255)}"

    def register(self, domain: str, created: datetime | date, ip_rep: tuple[float, float] | None,
                 verdict: str | None, country: str = "US", n_ips: int = 2) -> None:
        """Record a domain (and its sending IPs) in the threat-intel snapshot.

        ip_rep=None leaves the IPs out of the registry (fresh infrastructure: mocks answer heuristically).
        verdict=None leaves the domain out of URL feeds (feeds lag behind new phishing domains).
        """
        created_d = created.date() if isinstance(created, datetime) else created
        self.intel.domain_created.setdefault(domain, created_d.isoformat())
        if verdict:
            self.intel.url_verdicts[domain] = verdict
        if domain not in self.domain_ips:
            ips = [self.ip() for _ in range(n_ips)]
            self.domain_ips[domain] = ips
            if ip_rep:
                for ip in ips:
                    self.intel.ip_reputation[ip] = round(float(self.rng.uniform(*ip_rep)), 3)
                    self.intel.ip_country[ip] = country

    def legit_ip_rep(self) -> tuple[float, float]:
        """Most legit senders have clean IPs; a few sit on shared hosting that is blocklisted."""
        return (0.05, 0.18) if self.rng.random() < 0.05 else (0.6, 1.0)

    def old_date(self) -> date:
        return (self.start - timedelta(days=int(self.rng.integers(3 * 365, 25 * 365)))).date()

    def lookalike(self, domain: str) -> str:
        name, tld = domain.split(".", 1)
        for _ in range(20):
            kind = self.rng.integers(4)
            if kind == 0:
                pos = [i for i, c in enumerate(name) if c in HOMOGLYPHS]
                if not pos:
                    continue
                i = int(self.rng.choice(pos))
                cand = name[:i] + HOMOGLYPHS[name[i]] + name[i + 1:]
            elif kind == 1:
                cand = f"{name}-{self.rng.choice(['secure', 'billing', 'support', 'invoices', 'portal'])}"
            elif kind == 2:
                tld = str(self.rng.choice([t for t in ["com", "co", "net", "org", "cc"] if t != tld]))
                cand = name
            else:
                i = int(self.rng.integers(1, len(name) - 1))
                cand = name[:i] + name[i + 1:] if self.rng.random() < 0.5 else name[:i] + name[i] + name[i:]
            out = f"{cand}.{tld}"
            if out != domain:
                return out
        return f"{name}-secure.{tld}"

    def attacker_domain(self, base: str | None, campaign_start: datetime, aged_p: float = 0.1) -> str:
        """Lookalike of `base` (or a throwaway name) registered shortly before the campaign."""
        dom = self.lookalike(base) if base else \
            f"{self.fake.word()}{self.rng.choice(['-deals', 'promo', '-offers', 'mail', '-cloud'])}." \
            f"{self.rng.choice(['com', 'net', 'biz', 'info', 'shop'])}"
        aged = self.rng.random() < aged_p
        age = int(self.rng.integers(300, 900) if aged else self.rng.integers(1, 30))
        listed = self.rng.random() < 0.4
        self.register(dom, campaign_start - timedelta(days=age), (0.02, 0.15) if listed else None,
                      None, country=str(self.rng.choice(["RU", "NG", "VN", "BR", "RO", "US"])))
        return dom

    def landing_domain(self, created: datetime) -> str:
        """Phishing landing page domain; only some of these are already in URL feeds."""
        dom = f"{self.fake.word()}-{self.rng.choice(['login', 'verify', 'account', 'auth', 'sso'])}." \
              f"{self.rng.choice(['com', 'net', 'online', 'site', 'app'])}"
        verdict = self.rng.choice(["malicious", "suspicious", None], p=[0.4, 0.2, 0.4])
        self.register(dom, created - timedelta(days=int(self.rng.integers(1, 20))), None,
                      None if verdict is None else str(verdict))
        return dom

    # ---- tenants & correspondents -----------------------------------------------------------
    def person(self, domain: str, unique: bool = False) -> tuple[str, str]:
        """Employees get unique first names (display-name rule matches on them); outsiders may collide."""
        first = self.fake.unique.first_name() if unique else self.fake.first_name()
        last = self.fake.last_name()
        return f"{first.lower()}.{last.lower()}@{domain}", f"{first} {last}"

    def _build(self, n_tenants: int, n_mailboxes: int) -> None:
        for d in sorted(FREEMAIL_DOMAINS):              # sorted: set order varies per process
            self.register(d, self.old_date(), (0.7, 0.95), "clean", n_ips=6)
        for d in sorted(BRAND_DOMAINS | set(LEGIT_EXTRA_DOMAINS)):
            self.register(d, self.old_date(), (0.8, 1.0), "clean")
        for i, (name, domain, industry) in enumerate(TENANT_SPECS[:n_tenants]):
            tid = f"t{i:02d}"
            self.register(domain, self.old_date(), (0.85, 1.0), "clean")
            people = [self.person(domain, unique=True) for _ in range(n_mailboxes)]
            vendors, vendor_domains = [], []
            for _ in range(8):
                last, suffix = self.fake.last_name(), str(self.rng.choice(VENDOR_SUFFIXES))
                vdom = f"{last.lower()}{suffix}.com"
                vendor_domains.append(vdom)
                self.register(vdom, self.old_date(), self.legit_ip_rep(), "clean")
                vendors += [Contact(*self.person(vdom), vdom, f"{last} {suffix.title()}") for _ in range(2)]
            partners = []
            for _ in range(10):
                pdom = str(self.rng.choice(sorted(FREEMAIL_DOMAINS))) if self.rng.random() < 0.3 else \
                    f"{self.fake.last_name().lower()}{self.rng.choice(['consulting', 'co', 'advisors', 'hq'])}.com"
                if self.rng.random() < 0.1:                     # sister company: vendor name, other TLD
                    pdom = vendor_domains[int(self.rng.integers(8))].replace(".com", ".net")
                if pdom not in FREEMAIL_DOMAINS:
                    self.register(pdom, self.old_date(), self.legit_ip_rep(), "clean")
                partners.append(Contact(*self.person(pdom), pdom))
            self.tenants.append(Tenant(
                tenant_id=tid, name=name, domain=domain, industry=industry,
                mailboxes=[a for a, _ in people], names=dict(people),
                executives={r: people[j][0] for j, r in enumerate(ROLES)}, vendors=vendor_domains))
            self.vendors[tid], self.partners[tid] = vendors, partners


class Generator:
    def __init__(self, world: World) -> None:
        self.w, self.rng, self.fake = world, world.rng, world.fake
        self.n = 0
        self.progress = 0.0

    # ---- helpers ---------------------------------------------------------------------------
    def pick(self, seq):  # type: ignore[no-untyped-def]
        return seq[int(self.rng.integers(len(seq)))]

    def business_time(self) -> datetime:
        while True:
            d = self.w.start + timedelta(days=int(self.rng.integers(self.w.days)))
            if d.weekday() < 5 or self.rng.random() < 0.1:
                break
        return d + timedelta(hours=float(np.clip(self.rng.normal(12.5, 2.8), 6, 21)))

    def campaign_start(self) -> datetime:
        """Campaigns of a class march through the period (`progress` 0->1) with +-2 days of jitter,
        so every class lands in the time-based test split at roughly its overall rate."""
        span = 24 * (self.w.days - 2)
        hours = self.progress * span + self.rng.uniform(-48, 48)
        return self.w.start + timedelta(hours=float(np.clip(hours, 0, span)))

    def slots(self, tenant: Tenant, to: str, sender_name: str, **extra: str) -> dict[str, str]:
        to_name = tenant.names.get(to, "there")
        s = dict(first=to_name.split()[0], sender=sender_name or "Accounts Team",
                 topic=self.pick(T.INDUSTRY_TOPICS[tenant.industry.value]),
                 colleague=tenant.names[self.pick(tenant.mailboxes)],
                 day=self.pick(["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]),
                 inv=f"INV-{self.rng.integers(10000, 99999)}", po=f"PO-{self.rng.integers(1000, 9999)}",
                 amount=f"${self.rng.integers(2, 95) * 1000 + self.rng.integers(0, 999):,}.00",
                 item=self.pick(T.ITEMS), doc=self.pick(T.DOCS), pct=str(self.pick([50, 60, 70, 80, 90])),
                 country=self.pick(T.COUNTRIES), tenant_domain=tenant.domain, tenant_name=tenant.name,
                 vendor_name=self.pick(self.w.vendors[tenant.tenant_id]).vendor_name, url="", url2="")
        s.update(extra)
        return s

    def text(self, tpl: str, s: dict[str, str], wrap: bool = True) -> str:
        core = tpl.format(**s)
        for _ in range(int(self.rng.choice([0, 1, 2], p=[0.4, 0.4, 0.2]))):
            filler = self.pick(T.FILLERS)
            core = f"{filler} {core}" if self.rng.random() < 0.3 else f"{core} {filler}"
        if not wrap:
            return core
        return f"{self.pick(T.GREETINGS).format(**s)}\n\n{core}\n\n{self.pick(T.SIGNOFFS).format(**s)}"

    def auth(self, p_pass: float = 1.0, spoof: bool = False) -> AuthResults:
        if spoof:
            return AuthResults(spf="fail", dkim="none", dmarc="fail")
        if self.rng.random() < p_pass:
            return AuthResults()
        bad = lambda: str(self.pick(["softfail", "none", "fail"]))  # noqa: E731
        return AuthResults(spf=bad(), dkim=str(self.pick(["none", "fail"])), dmarc=str(self.pick(["none", "fail"])))

    def attachment(self, filename: str, malicious: bool = False, register_p: float = 0.6) -> Attachment:
        ext = filename.rsplit(".", 1)[-1]
        sha = "".join(self.rng.choice(list("0123456789abcdef"), 64))
        if malicious and self.rng.random() < register_p:
            self.w.intel.malware_hashes.add(sha)
        ctype = {"pdf": "application/pdf", "zip": "application/zip", "iso": "application/x-iso9660-image",
                 "xlsx": "application/vnd.ms-excel", "xlsm": "application/vnd.ms-excel",
                 "docm": "application/msword", "docx": "application/msword"}.get(ext, "application/octet-stream")
        return Attachment(filename=filename, content_type=ctype, sha256=sha,
                          size_bytes=int(self.rng.integers(20_000, 2_000_000)),
                          has_macro=ext in {"docm", "xlsm"})

    def email(self, tenant: Tenant, to: str, ts: datetime, from_addr: str, display: str, subject: str,
              body: str, category: str, scenario: str, auth: AuthResults | None = None, ip: str | None = None,
              urls: list[Url] | None = None, attachments: list[Attachment] | None = None,
              reply_to: str | None = None, thread: list[ThreadMessage] | None = None) -> Email:
        self.n += 1
        dom = from_addr.rsplit("@", 1)[-1]
        if ip is None:
            ip = self.pick(self.w.domain_ips[dom]) if dom in self.w.domain_ips else self.w.ip()
        return Email(
            message_id=f"<{self.n:06d}.{self.rng.integers(16**8):08x}@{dom}>", tenant_id=tenant.tenant_id,
            to_addr=to, timestamp=ts.replace(microsecond=0), from_addr=from_addr, from_display=display,
            reply_to=reply_to, subject=subject, body=body, auth=auth or AuthResults(), sender_ip=ip,
            urls=urls or [], attachments=attachments or [], thread=thread or [],
            thread_id=f"th{self.n:06d}" if thread else None,
            category=category, true_category=category, label=int(category != "legit"), scenario=scenario)

    def thread_of(self, to: str, ts: datetime, subject: str, body: str = "") -> list[ThreadMessage]:
        prior = ts - timedelta(hours=float(self.rng.uniform(1, 120)))
        return [ThreadMessage(from_addr=to, timestamp=prior.replace(microsecond=0),
                              subject=subject.removeprefix("Re: "), body=body)]

    # ---- legit ---------------------------------------------------------------------------
    def legit(self) -> Email:
        t: Tenant = self.pick(self.w.tenants)
        to, ts = self.pick(t.mailboxes), self.business_time()
        r = self.rng.random()
        if r < 0.15:
            return self.hard_negative(t, to, ts)
        if r < 0.45:                                            # internal
            sender = self.pick([m for m in t.mailboxes if m != to])
            s = self.slots(t, to, t.names[sender])
            subj, tpl = self.pick(T.LEGIT_INTERNAL)
            subj = subj.format(**s)
            atts = [self.attachment(self.pick(["notes.pdf", "summary.docx", "forecast.xlsx", "model.xlsm"]))] \
                if "notes" in subj.lower() or self.rng.random() < 0.1 else []
            thread = self.thread_of(to, ts, subj) if subj.startswith("Re:") or self.rng.random() < 0.2 else None
            return self.email(t, to, ts, sender, t.names[sender], subj, self.text(tpl, s), "legit",
                              "legit:internal", attachments=atts, thread=thread)
        if r < 0.75:                                            # vendor
            c: Contact = self.pick(self.w.vendors[t.tenant_id])
            url = f"https://portal.{c.domain}/orders/{self.rng.integers(1000, 9999)}"
            s = self.slots(t, to, c.name, url=url, vendor_name=c.vendor_name)
            subj, tpl = self.pick(T.LEGIT_VENDOR)
            subj = subj.format(**s)
            atts = [self.attachment(f"{s['inv']}.pdf" if "Invoice" in subj else "quote.pdf")] \
                if any(k in subj for k in ("Invoice", "Quote", "price")) else []
            urls = [Url(href=url, anchor_text=url)] if "{url}" in tpl else []
            thread = self.thread_of(to, ts, subj) if subj.startswith("Re:") or self.rng.random() < 0.3 else None
            return self.email(t, to, ts, c.addr, c.name, subj, self.text(tpl, s), "legit", "legit:vendor",
                              auth=self.auth(0.95), urls=urls, attachments=atts, thread=thread)
        if r < 0.90:                                            # partners / customers (some on freemail)
            c = self.pick(self.w.partners[t.tenant_id])
            if self.rng.random() < 0.2:                         # real OneDrive / SharePoint share
                url = self.pick([f"https://onedrive.live.com/view?id={self.rng.integers(16**8):08x}",
                                 f"https://{t.domain.split('.')[0]}-my.sharepoint.com/:w:/{self.rng.integers(16**8):08x}"])
                s = self.slots(t, to, c.name, url=url)
                subj, tpl = self.pick(T.LEGIT_SHARED_DOC)
                return self.email(t, to, ts, c.addr, c.name, subj.format(**s), self.text(tpl, s), "legit",
                                  "legit:shared_doc", auth=self.auth(0.95),
                                  urls=[Url(href=url, anchor_text=self.pick(["Open in OneDrive", url]))])
            s = self.slots(t, to, c.name)
            subj, tpl = self.pick(T.LEGIT_INTERNAL[:5])
            subj = subj.format(**s)
            return self.email(t, to, ts, c.addr, c.name, subj, self.text(tpl, s), "legit", "legit:partner",
                              auth=self.auth(0.93),
                              thread=self.thread_of(to, ts, subj) if self.rng.random() < 0.3 else None)
        display, from_addr, subj, tpl = self.pick(T.LEGIT_NOTIFICATION)  # SaaS notifications, newsletters
        dom = from_addr.split("@")[1]
        url, url2 = f"https://{dom}/r/{self.rng.integers(16**6):06x}", f"https://{dom}/unsubscribe"
        s = self.slots(t, to, display, url=url, url2=url2)
        urls = [Url(href=url, anchor_text="View")] + ([Url(href=url2, anchor_text="Unsubscribe")]
                                                       if "{url2}" in tpl else [])
        # Notification platforms often set Reply-To to a person or a separate domain.
        reply_to = self.pick([self.pick(t.mailboxes), f"editors@{dom.split('.')[0]}-news.com"]) \
            if self.rng.random() < 0.3 else None
        return self.email(t, to, ts, from_addr, display, subj.format(**s), self.text(tpl, s, wrap=False),
                          "legit", "legit:notification", urls=urls, reply_to=reply_to)

    def hard_negative(self, t: Tenant, to: str, ts: datetime) -> Email:
        kind = self.pick(["exec_urgent_payment", "it_password", "promo", "new_vendor", "vendor_bank_change",
                          "personal_account", "encrypted_zip", "rebrand", "internal_tool", "exec_gift_cards",
                          "vendor_payment_request", "exec_urgent_payment", "it_password", "vendor_payment_request"])
        ex = t.executives
        sc = f"hard_neg:{kind}"
        if kind == "exec_urgent_payment":
            sender, to = ex["CFO"], self.pick([ex["AP"], ex["Controller"]])
            s = self.slots(t, to, t.names[sender])
            subj, tpl = self.pick(T.HN_EXEC_URGENT_PAYMENT)
            return self.email(t, to, ts, sender, t.names[sender], subj.format(**s), self.text(tpl, s), "legit", sc)
        if kind == "vendor_payment_request":                   # real vendor chasing payment
            v: Contact = self.pick(self.w.vendors[t.tenant_id])
            to = self.pick([ex["AP"], ex["CFO"], ex["Controller"]])
            s = self.slots(t, to, v.name, vendor_name=v.vendor_name)
            subj, tpl = self.pick(T.HN_VENDOR_PAYMENT_REQUEST)
            return self.email(t, to, ts, v.addr, v.name, subj.format(**s), self.text(tpl, s), "legit", sc,
                              attachments=[self.attachment(f"{s['inv']}.pdf")])
        if kind == "exec_gift_cards":                          # real exec, same words as the BEC version
            sender = self.pick([ex["CEO"], ex["HR"]])
            s = self.slots(t, to, t.names[sender])
            subj, tpl = T.BEC_GIFT_CARDS[1]
            return self.email(t, to, ts, sender, t.names[sender], subj, self.text(tpl, s), "legit", sc)
        if kind == "it_password":
            url = f"https://password.{t.domain}/reset"
            s = self.slots(t, to, "IT Service Desk", url=url)
            subj, tpl = self.pick(T.HN_IT_PASSWORD)
            return self.email(t, to, ts, ex["IT"], "IT Service Desk", subj, self.text(tpl, s), "legit", sc,
                              urls=[Url(href=url, anchor_text=url)])
        if kind == "promo":
            url, url2 = f"https://{PROMO_DOMAIN}/upgrade?c=annual30", f"https://{PROMO_DOMAIN}/unsubscribe"
            s = self.slots(t, to, "SaaSMetrics", url=url, url2=url2)
            subj, tpl = T.HN_PROMO
            return self.email(t, to, ts, f"offers@{PROMO_DOMAIN}", "SaaSMetrics", subj, self.text(tpl, s, False),
                              "legit", sc,
                              urls=[Url(href=url, anchor_text="Upgrade now"), Url(href=url2, anchor_text="Unsubscribe")])
        if kind in ("new_vendor", "rebrand"):                   # first-time sender
            last, suffix = self.fake.last_name(), str(self.pick(VENDOR_SUFFIXES))
            dom = f"{last.lower()}{suffix}{'-group' if kind == 'rebrand' else ''}.com"
            created = (ts - timedelta(days=int(self.rng.integers(5, 25)))) if kind == "rebrand" else self.w.old_date()
            self.w.register(dom, created, self.w.legit_ip_rep(), "clean")
            addr, name = self.w.person(dom)
            s = self.slots(t, to, name, vendor_name=f"{last} {suffix.title()}")
            subj, tpl = T.HN_NEW_VENDOR if kind == "new_vendor" else T.HN_REBRAND
            atts = [self.attachment("capabilities.pdf")] if kind == "new_vendor" else []
            return self.email(t, to, ts, addr, name, subj.format(**s), self.text(tpl, s), "legit", sc,
                              attachments=atts)
        if kind == "personal_account":                          # employee writing from personal freemail
            emp = self.pick(t.mailboxes[6:])
            name = t.names[emp]
            addr = f"{name.lower().replace(' ', '.')}{self.rng.integers(1, 99)}@{self.pick(sorted(FREEMAIL_DOMAINS))}"
            s = self.slots(t, to, name)
            subj, tpl = T.HN_PERSONAL_ACCOUNT
            return self.email(t, to, ts, addr, name, subj, self.text(tpl, s), "legit", sc)
        if kind == "encrypted_zip":                             # legit password-protected archive
            c: Contact = self.pick(self.w.partners[t.tenant_id] + self.w.vendors[t.tenant_id])
            s = self.slots(t, to, c.name)
            subj, tpl = T.HN_ENCRYPTED_ZIP
            return self.email(t, to, ts, c.addr, c.name, subj.format(**s), self.text(tpl, s), "legit", sc,
                              attachments=[self.attachment(f"documents_{s['inv']}.zip")],
                              thread=self.thread_of(to, ts, subj.format(**s)))
        if kind == "internal_tool":                             # SaaS tool sending as the tenant, DMARC unaligned
            s = self.slots(t, to, f"{t.name} Events", url=f"https://events.{t.domain}/rsvp")
            return self.email(t, to, ts, f"events@{t.domain}", f"{t.name} Events", "Team offsite: please RSVP",
                              self.text("Please RSVP for the team offsite on {day} here: {url}", s), "legit", sc,
                              auth=AuthResults(spf="softfail", dkim="none", dmarc="fail"), ip=self.w.ip(),
                              urls=[Url(href=s["url"], anchor_text="RSVP")])
        v = self.pick(self.w.vendors[t.tenant_id])              # legit vendor announcing a bank change
        to = self.pick([ex["AP"], ex["CFO"], ex["Controller"]])
        s = self.slots(t, to, v.name)
        subj, tpl = T.HN_VENDOR_BANK_CHANGE
        return self.email(t, to, ts, v.addr, v.name, subj, self.text(tpl, s), "legit", sc,
                          attachments=[self.attachment("bank_details.pdf")])

    # ---- attack campaigns ------------------------------------------------------------------
    def targets(self, k: int, n_tenants: int) -> list[tuple[Tenant, str]]:
        ts = [self.w.tenants[i] for i in self.rng.choice(len(self.w.tenants), n_tenants, replace=False)]
        return [(t, self.pick(t.mailboxes)) for t in (self.pick(ts) for _ in range(k))]

    def spread(self, start: datetime, k: int, hours: float) -> list[datetime]:
        return sorted(start + timedelta(hours=float(h)) for h in self.rng.uniform(0, hours, k))

    def spam_campaign(self, k: int) -> list[Email]:
        start = self.campaign_start()
        dom = self.w.attacker_domain(None, start)
        created = datetime.fromisoformat(self.w.intel.domain_created[dom])
        self.w.intel.domain_created[dom] = (created - timedelta(days=int(self.rng.integers(0, 500)))).date().isoformat()
        self.w.intel.url_verdicts[dom] = str(self.pick(["suspicious", "malicious", "suspicious"]))
        subj_t, tpl = self.pick(T.SPAM)
        cold_outreach = "{item}" in tpl                         # B2B sales spam: a "person", often on freemail
        if cold_outreach:
            first, last = self.fake.first_name(), self.fake.last_name()
            display = f"{first} {last}"
            sdom = str(self.pick(sorted(FREEMAIL_DOMAINS))) if self.rng.random() < 0.4 else dom
            sender = f"{first.lower()}.{last.lower()}@{sdom}"
        else:
            sender, display = f"{self.pick(['news', 'deals', 'info', 'promo'])}@{dom}", self.fake.company()
        p_pass = float(self.rng.uniform(0.2, 0.9))
        out = []
        for (t, to), ts in zip(self.targets(k, int(self.rng.integers(2, 6))), self.spread(start, k, 36)):
            href = f"https://bit.ly/{self.rng.integers(16**6):06x}" if self.rng.random() < 0.2 else \
                f"http://{dom}/p/{self.rng.integers(16**6):06x}"
            s = self.slots(t, to, display, url=href, url2=f"http://{dom}/unsub")
            urls = [Url(href=href, anchor_text="Book a time" if cold_outreach else "Shop now")]
            if "{url2}" in tpl:
                urls.append(Url(href=s["url2"], anchor_text="unsubscribe"))
            out.append(self.email(t, to, ts, sender, display, subj_t.format(**s), self.text(tpl, s, cold_outreach),
                                  "spam", "spam:cold_outreach" if cold_outreach else "spam:bulk",
                                  auth=self.auth(p_pass), urls=urls))
        return out

    def phishing_campaign(self, k: int) -> list[Email]:
        start = self.campaign_start()
        kind = self.pick(["brand", "brand", "tenant_it", "compromised_account"])
        if kind == "compromised_account":                       # hard positive: real, trusted sender
            t = self.pick(self.w.tenants)
            c: Contact = self.pick(self.w.vendors[t.tenant_id] + self.w.partners[t.tenant_id])
            # Attackers often host the credential page on real SharePoint: clean, decades-old domain.
            land = "sharepoint.com" if self.rng.random() < 0.4 else self.w.landing_domain(start)
            out = []
            for ts in self.spread(start, min(k, 3), 6):
                to = self.pick(t.mailboxes)
                href = f"https://{c.domain.split('.')[0]}-my.{land}/:b:/{self.rng.integers(16**8):08x}" \
                    if land == "sharepoint.com" else f"https://{land}/onedrive/{self.rng.integers(16**8):08x}"
                s = self.slots(t, to, c.name, url=href)
                subj, tpl = self.pick(T.LEGIT_SHARED_DOC)        # same words as a real share
                out.append(self.email(t, to, ts, c.addr, c.name, subj.format(**s), self.text(tpl, s),
                                      "phishing", "hard_pos:compromised_account",
                                      urls=[Url(href=href, anchor_text="Open in OneDrive")]))
            return out
        plain = self.rng.random() < P_PLAIN["phishing"]
        if kind == "brand":
            if plain:                                           # word-for-word copy of a real notification
                display, _, subj_t, tpl = self.pick([n for n in T.LEGIT_NOTIFICATION if n[0] in BRAND_SENDERS])
            else:
                display, subj_t, tpl = self.pick(T.PHISH_BRAND)
            brand = BRAND_SENDERS[display]
            dom = self.w.attacker_domain(brand, start)
            anchor = f"https://login.{brand}/"
            tgt = self.targets(k, int(self.rng.integers(1, 4)))
        else:
            t = self.pick(self.w.tenants)
            display, subj_t, tpl = self.pick(T.PHISH_TENANT_IT)
            if plain:
                subj_t, tpl = self.pick(T.HN_IT_PASSWORD)
            dom = self.w.attacker_domain(t.domain, start)
            anchor = f"https://password.{t.domain}/"
            tgt = [(t, self.pick(t.mailboxes)) for _ in range(k)]
        land = self.w.landing_domain(start) if self.rng.random() < 0.7 else dom
        if land == dom:
            self.w.intel.url_verdicts.setdefault(dom, str(self.pick(["malicious", "suspicious"])))
        sender = f"{self.pick(['no-reply', 'security', 'support', 'admin'])}@{dom}"
        p_pass = float(self.rng.choice([0.9, 0.3]))
        out = []
        for (t, to), ts in zip(tgt, self.spread(start, len(tgt), 24)):
            href = f"https://{land}/{self.pick(['login', 'verify', 'secure'])}?id={self.rng.integers(16**8):08x}"
            s = self.slots(t, to, display, url=href)
            out.append(self.email(t, to, ts, sender, display, subj_t.format(**s), self.text(tpl, s, False),
                                  "phishing", f"phishing:{kind}", auth=self.auth(p_pass),
                                  urls=[Url(href=href, anchor_text=self.pick([anchor, "Review", "Sign in"]))]))
        return out

    def bec_campaign(self, k: int) -> list[Email]:
        start = self.campaign_start()
        t: Tenant = self.pick(self.w.tenants)
        ex = t.executives
        kind = self.pick(["gift_cards", "gift_cards", "wire_lookalike", "wire_freemail", "payroll", "direct_spoof",
                          "vendor_invoice", "vendor_invoice", "compromised_vendor"])
        plain = self.rng.random() < P_PLAIN["bec"]
        out = []
        for ts in self.spread(start, k, 8):
            free = str(self.pick(sorted(FREEMAIL_DOMAINS)))
            reply_to, atts, thread, auth = None, [], None, AuthResults()
            if kind in ("gift_cards", "wire_lookalike", "wire_freemail", "direct_spoof"):
                display = t.names[ex["CEO"]]
                first, last = display.lower().split(" ", 1)
                to = self.pick(t.mailboxes[6:]) if kind == "gift_cards" else \
                    self.pick([ex["CFO"], ex["Controller"], ex["AP"]])
                subj, tpl = self.pick(T.HN_EXEC_URGENT_PAYMENT if plain else
                                      T.BEC_GIFT_CARDS if kind == "gift_cards" else T.BEC_WIRE)
                if kind in ("gift_cards", "wire_freemail"):
                    sender = f"{first}.{last}.{self.pick(['office', 'ceo', 'exec', 'mobile'])}@{free}"
                    if self.rng.random() < 0.3:                 # display name variant dodges exact matching
                        display = f"{display} (CEO)"
                    reply_to = f"{first}{self.rng.integers(10, 99)}@{free}" if self.rng.random() < 0.3 else None
                elif kind == "wire_lookalike":
                    sender = f"{first}.{last}@{self.w.attacker_domain(t.domain, start)}"
                    reply_to = f"{first}.{last}.private@{free}" if self.rng.random() < 0.6 else None
                    auth = self.auth(0.6)
                else:
                    sender, auth = ex["CEO"], self.auth(spoof=True)
                    reply_to = f"{first}.{last}@{free}"
            elif kind == "payroll":
                victim = self.pick(t.mailboxes[6:])
                display = t.names[victim]
                sender = f"{display.lower().replace(' ', '.')}{self.rng.integers(1, 99)}@{free}"
                to = ex["HR"]
                subj, tpl = self.pick(T.BEC_PAYROLL)
            else:
                v: Contact = self.pick(self.w.vendors[t.tenant_id])
                display, to = v.name, self.pick([ex["AP"], ex["CFO"], ex["Controller"]])
                mimic = kind == "compromised_vendor" and self.rng.random() < 0.5
                subj, tpl = self.pick(T.HN_VENDOR_PAYMENT_REQUEST if mimic or plain else T.BEC_VENDOR_INVOICE)
                atts = [self.attachment(self.pick(["new_bank_details.pdf", "bank_details.pdf", "invoice.pdf"]))]
                if kind == "vendor_invoice":
                    sender = f"{v.addr.split('@')[0]}@{self.w.attacker_domain(v.domain, start)}"
                    reply_to = f"accounts.{v.domain.split('.')[0]}@{free}" if self.rng.random() < 0.4 else None
                    auth = self.auth(0.7)
                else:                                           # hard positive: real vendor mailbox taken over
                    sender = v.addr
                    thread = self.thread_of(to, ts, f"Invoice {self.rng.integers(10000, 99999)}",
                                            "Thanks, we have received the invoice and scheduled it.")
            s = self.slots(t, to, display)
            scenario = f"hard_pos:{kind}" if kind == "compromised_vendor" else f"bec:{kind}"
            out.append(self.email(t, to, ts, sender, display, subj.format(**s), self.text(tpl, s), "bec",
                                  scenario, auth=auth, reply_to=reply_to, attachments=atts, thread=thread))
        return out

    def malware_campaign(self, k: int) -> list[Email]:
        start = self.campaign_start()
        if self.rng.random() < 0.15:                            # hard positive: password zip from known contact
            t = self.pick(self.w.tenants)
            c: Contact = self.pick(self.w.vendors[t.tenant_id] + self.w.partners[t.tenant_id])
            out = []
            for ts in self.spread(start, min(k, 3), 6):
                to = self.pick(t.mailboxes)
                s = self.slots(t, to, c.name)
                subj, tpl, fname = T.MALWARE_PASSWORD_ZIP if self.rng.random() < 0.5 else \
                    (*T.HN_ENCRYPTED_ZIP, "documents_{inv}.zip")
                out.append(self.email(t, to, ts, c.addr, c.name, subj.format(**s), self.text(tpl, s), "malware",
                                      "hard_pos:password_zip",
                                      attachments=[self.attachment(fname.format(**s), True, register_p=0.0)],
                                      thread=self.thread_of(to, ts, subj.format(**s))))
            return out
        subj_t, tpl, fname = self.pick(T.MALWARE)
        if self.rng.random() < P_PLAIN["malware"]:              # ordinary vendor wording, risky attachment
            subj_t, tpl = self.pick([T.LEGIT_VENDOR[0], T.LEGIT_VENDOR[1], T.LEGIT_VENDOR[3]])
        dom = self.w.attacker_domain("dhl.com" if "DHL" in subj_t else None, start, aged_p=0.3)
        sender, display = f"{self.pick(['billing', 'accounts', 'notice', 'scanner'])}@{dom}", self.fake.company()
        p_pass = float(self.rng.choice([0.8, 0.3]))
        out = []
        for (t, to), ts in zip(self.targets(k, int(self.rng.integers(1, 4))), self.spread(start, k, 24)):
            s = self.slots(t, to, display)
            out.append(self.email(t, to, ts, sender, display, subj_t.format(**s), self.text(tpl, s), "malware",
                                  "malware:attachment", auth=self.auth(p_pass),
                                  attachments=[self.attachment(fname.format(**s), True)]))
        return out


CAMPAIGN_SIZE = {"spam": (5, 25), "phishing": (2, 8), "bec": (1, 3), "malware": (3, 10)}


def add_label_noise(emails: list[Email], rate: float, rng: np.random.Generator) -> int:
    """Flip ~rate of observed labels the way user reports go wrong (newsletters reported as spam, etc.)."""
    idx = rng.choice(len(emails), int(rate * len(emails)), replace=False)
    for i in idx:
        e = emails[i]
        if e.true_category == "legit":
            e.category = str(rng.choice(["spam", "phishing"], p=[0.8, 0.2]))
        elif e.true_category == "spam":
            e.category = "legit"
        else:
            e.category = str(rng.choice(["legit", "spam"], p=[0.6, 0.4]))
        e.label = int(e.category != "legit")
    return len(idx)


def generate(cfg: dict) -> tuple[list[Tenant], list[Email], ThreatIntel, int]:
    world = World(cfg)
    gen = Generator(world)
    dcfg = cfg["data"]
    target = {c: int(round(f * dcfg["n_emails"])) for c, f in dcfg["class_mix"].items()}
    emails = [gen.legit() for _ in range(target["legit"])]
    builders = {"spam": gen.spam_campaign, "phishing": gen.phishing_campaign,
                "bec": gen.bec_campaign, "malware": gen.malware_campaign}
    for cat, build in builders.items():
        made = 0
        while made < target[cat]:
            lo, hi = CAMPAIGN_SIZE[cat]
            gen.progress = made / target[cat]
            batch = build(min(int(gen.rng.integers(lo, hi + 1)), target[cat] - made))
            emails += batch
            made += len(batch)
    end = world.start + timedelta(days=world.days)
    emails = sorted((e for e in emails if e.timestamp < end), key=lambda e: e.timestamp)
    n_noisy = add_label_noise(emails, dcfg["label_noise"], gen.rng)
    return world.tenants, emails, world.intel, n_noisy


def write_outputs(cfg: dict, tenants: list[Tenant], emails: list[Email], intel: ThreatIntel) -> None:
    raw, sample = Path(cfg["paths"]["raw"]), Path(cfg["paths"]["sample"])
    raw.mkdir(parents=True, exist_ok=True)
    sample.mkdir(parents=True, exist_ok=True)
    tenants_json = json.dumps([t.model_dump(mode="json") for t in tenants], indent=1)
    (raw / "tenants.json").write_text(tenants_json)
    (sample / "tenants.json").write_text(tenants_json)
    intel.save(raw / "intel.json")
    with open(raw / "emails.jsonl", "w") as f:
        f.writelines(e.model_dump_json() + "\n" for e in emails)
    # Committed sample: 300 legit + 50 of each attack class (oversampled so every class is visible).
    rng = np.random.default_rng(cfg["seed"])
    picked: list[int] = []
    for cat, n in {"legit": 300, "spam": 50, "phishing": 50, "bec": 50, "malware": 50}.items():
        idx = [i for i, e in enumerate(emails) if e.true_category == cat]
        picked += rng.choice(idx, min(n, len(idx)), replace=False).tolist()
    with open(sample / "emails_sample.jsonl", "w") as f:
        f.writelines(emails[i].model_dump_json() + "\n" for i in sorted(picked))


def print_stats(cfg: dict, emails: list[Email], n_noisy: int) -> None:
    n = len(emails)
    split = datetime.combine(date.fromisoformat(str(cfg["data"]["start_date"])), datetime.min.time()) + \
        timedelta(days=cfg["data"]["days"] - cfg["data"]["test_days"])
    true, obs = Counter(e.true_category for e in emails), Counter(e.category for e in emails)
    test = Counter(e.true_category for e in emails if e.timestamp >= split)
    print(f"\n{n} emails, {len({e.tenant_id for e in emails})} tenants, "
          f"{emails[0].timestamp:%Y-%m-%d} -> {emails[-1].timestamp:%Y-%m-%d}, test split at {split:%Y-%m-%d}")
    print(f"\n{'class':<10}{'true':>7}{'%':>7}{'labelled':>10}{'train':>7}{'test':>6}")
    for c in ("legit", "spam", "phishing", "bec", "malware"):
        print(f"{c:<10}{true[c]:>7}{100 * true[c] / n:>6.1f}%{obs[c]:>10}{true[c] - test[c]:>7}{test[c]:>6}")
    hard = Counter(e.scenario for e in emails if e.scenario and e.scenario.startswith("hard_"))
    print(f"\nlabel noise: {n_noisy} flipped ({100 * n_noisy / n:.1f}%)")
    print("hard cases:  " + ", ".join(f"{k} {v}" for k, v in sorted(hard.items())))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--config", default=None)
    cfg = load_config(ap.parse_args().config)
    tenants, emails, intel, n_noisy = generate(cfg)
    write_outputs(cfg, tenants, emails, intel)
    print(f"wrote {cfg['paths']['raw']}/{{emails.jsonl,tenants.json,intel.json}} and {cfg['paths']['sample']}/")
    print_stats(cfg, emails, n_noisy)


if __name__ == "__main__":
    main()
