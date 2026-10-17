"""bec-guard demo: classify a curated example or a pasted email and see why.

Run: make demo   (needs `make data train` first)
"""
from __future__ import annotations

import re
import sys
import uuid
from datetime import timedelta
from pathlib import Path

import matplotlib
import numpy as np
import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.common.config import load_config  # noqa: E402
from src.data.io import load_emails, load_tenants  # noqa: E402
from src.data.schema import Action, Attachment, AuthResults, Email, Url  # noqa: E402
from src.features.extract import FEATURES  # noqa: E402
from src.models.train import split_dates  # noqa: E402
from src.pipeline.cascade import Cascade, Verdict  # noqa: E402
from src.rules.engine import RULES  # noqa: E402

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

# (name, which emails qualify, which verdict we want to show). The first qualifying test email whose
# verdict matches is used, so the set covers every tier plus one honest miss.
EXAMPLES = [
    ("Routine vendor invoice", lambda e: e.scenario == "legit:vendor" and e.subject.startswith("Invoice"),
     lambda v: v.action == Action.DELIVER),
    ("Real CFO asks for an urgent wire (legit)", lambda e: e.scenario == "hard_neg:exec_urgent_payment",
     lambda v: v.action == Action.DELIVER),
    ("Lookalike-domain credential phish (Tier 0)", lambda e: e.scenario in ("phishing:brand", "phishing:tenant_it"),
     lambda v: v.tier == 0),
    ("CEO gift-card request from a freemail account", lambda e: e.scenario == "bec:gift_cards",
     lambda v: v.action == Action.QUARANTINE),
    ("Gray zone: decided by the intent check (Tier 2)", lambda e: e.true_category != "legit",
     lambda v: v.tier == 2),
    ("Invoice with a macro attachment", lambda e: e.scenario == "malware:attachment"
     and any(a.filename.endswith((".docm", ".xlsm")) for a in e.attachments), lambda v: v.action == Action.QUARANTINE),
    ("Missed: hijacked vendor account asks to pay a new account",
     lambda e: e.scenario == "hard_pos:compromised_vendor", lambda v: v.action == Action.DELIVER),
]
REASONS = {r.code: r.description for r in RULES} | {
    "MODEL_HIGH_RISK": "LightGBM is confident this is malicious",
    "ASKS_PAYMENT": "Asks for a payment, wire or bank-detail change",
    "ASKS_GIFT_CARD": "Asks for gift cards",
    "ASKS_CREDENTIAL": "Asks the reader to sign in or share a password",
    "NEW_SENDER": "First email from this sender to this company",
    "TOPIC_SHIFT": "Very different from what this sender usually writes",
    "FREEMAIL_SENDER": "New sender on a free webmail domain",
    "VIRUS_DETECTED": "Attachment scan found malware; email pulled from the mailbox",
}
ACTION_STYLE = {Action.DELIVER: ("success", "Delivered"), Action.WARNING_BANNER: ("warning", "Delivered with a warning banner"),
                Action.SPAM_FOLDER: ("warning", "Moved to spam folder"), Action.QUARANTINE: ("error", "Quarantined")}
# Diverging pair from the chart palette: red = toward attack, blue = toward legit.
RED, BLUE, SURFACE, INK_2, GRID = "#e34948", "#2a78d6", "#fcfcfb", "#52514e", "#e4e3df"


@st.cache_resource(show_spinner="Loading models and sender history...")
def load() -> tuple:
    import shap

    cfg = load_config()
    raw = Path(cfg["paths"]["raw"])
    cascade = Cascade.load(cfg, simulate_latency=True)       # history as of the train/test split
    _, test_start = split_dates(cfg)
    test = [e for e in load_emails(raw / "emails.jsonl")
            if e.timestamp >= test_start and e.category == e.true_category]
    picker = Cascade.load(cfg)                                  # no simulated latency, for choosing examples
    examples = {}
    for name, qualifies, wanted in EXAMPLES:
        candidates = [e for e in test if qualifies(e)]
        examples[name] = next((e for e in candidates if wanted(picker.classify(e))), candidates[0])
    return cfg, cascade, load_tenants(raw / "tenants.json"), examples, test_start, shap.TreeExplainer(cascade.lgbm)


def shap_chart(explainer, verdict: Verdict, top: int = 10) -> plt.Figure:
    """Contributions toward 'malicious' (minus the legit-class SHAP value) for this one email."""
    X = pd.DataFrame([verdict.features], columns=FEATURES)
    sv = explainer.shap_values(X)
    legit = (sv[0] if isinstance(sv, list) else np.asarray(sv)[..., 0])
    contrib = pd.Series(-np.asarray(legit).reshape(-1), index=FEATURES)
    contrib = contrib[contrib.abs().nlargest(top).index].sort_values()
    labels = [f"{f} = {verdict.features[f]:.2f}" if not np.isnan(verdict.features[f]) else f"{f} = n/a"
              for f in contrib.index]
    fig, ax = plt.subplots(figsize=(6.4, 0.42 * len(contrib) + 0.9), facecolor=SURFACE)
    ax.barh(labels, contrib.values, color=[RED if v > 0 else BLUE for v in contrib.values], height=0.6)
    ax.axvline(0, color=INK_2, linewidth=0.8)
    ax.set_facecolor(SURFACE)
    for s in ("top", "right", "left"):
        ax.spines[s].set_visible(False)
    ax.spines["bottom"].set_color(GRID)
    ax.tick_params(colors=INK_2, labelsize=9, length=0)
    ax.set_xlabel("<- toward legit      SHAP contribution      toward attack ->", color=INK_2, fontsize=9)
    fig.tight_layout()
    return fig


def show_email(e: Email) -> None:
    hdr = f"**From:** {e.from_display} <{e.from_addr}>  \n**To:** {e.to_addr}"
    if e.reply_to:
        hdr += f"  \n**Reply-To:** {e.reply_to}"
    hdr += f"  \n**Subject:** {e.subject}  \n**Auth:** SPF {e.auth.spf}, DKIM {e.auth.dkim}, DMARC {e.auth.dmarc}"
    if e.attachments:
        hdr += "  \n**Attachments:** " + ", ".join(a.filename for a in e.attachments)
    st.markdown(hdr)
    st.text(e.body)


def pasted_email(tenants, test_start) -> Email | None:
    t = st.selectbox("Recipient company", tenants, format_func=lambda t: f"{t.name} ({t.domain})")
    with st.form("paste"):
        c1, c2 = st.columns(2)
        to = c1.selectbox("To", t.mailboxes, format_func=lambda a: f"{t.names[a]} <{a}>")
        display = c2.text_input("From display name", t.names[t.executives["CEO"]])
        from_addr = c1.text_input("From address", "ceo.office.desk@gmail.com")
        reply_to = c2.text_input("Reply-To (optional)", "")
        subject = st.text_input("Subject", "Quick favor")
        body = st.text_area("Body", "Are you at your desk? I need you to buy some gift cards for a client event. "
                                    "I'm in meetings all day, reply with the codes.", height=140)
        c3, c4, c5, c6 = st.columns(4)
        spf = c3.selectbox("SPF", ["pass", "fail", "softfail", "none"])
        dkim = c4.selectbox("DKIM", ["pass", "fail", "none"])
        dmarc = c5.selectbox("DMARC", ["pass", "fail", "none"])
        ip = c6.text_input("Sender IP", "198.51.100.23")
        atts = st.text_input("Attachment file names (comma separated, optional)", "")
        if not st.form_submit_button("Classify", type="primary"):
            return None
    urls = [Url(href=u, anchor_text=u) for u in re.findall(r"https?://\S+", body)]
    return Email(message_id=f"<{uuid.uuid4().hex}@demo>", tenant_id=t.tenant_id, to_addr=to,
                 timestamp=test_start + timedelta(days=1), from_addr=from_addr.strip(), from_display=display,
                 reply_to=reply_to.strip() or None, subject=subject, body=body,
                 auth=AuthResults(spf=spf, dkim=dkim, dmarc=dmarc), sender_ip=ip.strip(), urls=urls,
                 attachments=[Attachment(filename=f.strip(), has_macro=f.strip().lower().endswith((".docm", ".xlsm", ".pptm")))
                              for f in atts.split(",") if f.strip()])


def show_verdict(cascade: Cascade, explainer, email: Email) -> None:
    v = cascade.classify(email)
    kind, label = ACTION_STYLE[v.action]
    getattr(st, kind)(f"**{v.action.value}**: {label}")
    m = st.columns(4)
    m[0].metric("Predicted class", v.category)
    m[1].metric("P(malicious)", f"{v.score:.2f}")
    m[2].metric("Decided at", f"Tier {v.tier}")
    m[3].metric("Latency", f"{v.latency_ms:.0f} ms")
    st.caption("Tier 0 = rules, Tier 1 = text score + LightGBM, Tier 2 = intent check for gray-zone scores "
               f"({cascade.lo:.2f}–{cascade.hi:.2f}).")

    left, right = st.columns([1, 1.3])
    with left:
        st.subheader("Reasons")
        if v.reasons:
            for code in v.reasons:
                st.markdown(f"- `{code}`: {REASONS.get(code, '')}")
        else:
            st.markdown("No rule fired and the model sees nothing unusual.")
        if v.intents:
            st.subheader("Intent check")
            st.dataframe(pd.DataFrame({"probability": v.intents}).style.format("{:.2f}"), width="content")
    with right:
        st.subheader("Why the model scored it this way")
        st.pyplot(shap_chart(explainer, v), clear_figure=True)

    if v.scans:
        with st.spinner("Attachment scan running asynchronously (the decision above did not wait for it)..."):
            v2, scan_ms = Cascade.remediate(v, timeout_s=90)
        if scan_ms is not None:
            st.error(f"Async scan: infected after {scan_ms / 1000:.1f}s. Email pulled from the mailbox.")
        else:
            st.info("Async scan: no malware found (or the email was already quarantined).")


def main() -> None:
    st.set_page_config(page_title="bec-guard demo", layout="wide")
    st.title("bec-guard")
    st.write("Tiered spam / phishing / BEC filter. Pick an example from the held-out test period or paste "
             "your own email. Sender history is as of the train/test split.")
    try:
        cfg, cascade, tenants, examples, test_start, explainer = load()
    except FileNotFoundError:
        st.error("Models not found. Run `make data train` first.")
        return

    mode = st.sidebar.radio("Input", ["Curated example", "Paste an email"])
    if mode == "Curated example":
        name = st.sidebar.radio("Example", list(examples))
        e = examples[name]
        st.sidebar.caption(f"Ground truth: **{e.true_category}** ({e.scenario})")
        with st.expander("Email", expanded=True):
            show_email(e)
        show_verdict(cascade, explainer, e)
    else:
        e = pasted_email(tenants, test_start)
        if e is not None:
            show_verdict(cascade, explainer, e)


if __name__ == "__main__":         # streamlit runs the script as __main__
    main()
