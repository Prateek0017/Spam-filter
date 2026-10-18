"""Evaluate the cascade on the held-out period and write reports/.

The cascade is replayed over the real stream: train-period emails only build sender history
(mail whose observed label is legit stands in for "delivered"), then every test email is
classified live (features, rules, models, intent check, virus scan) and added to history
afterwards; only test emails the cascade delivered earn trust. All metrics use the *true*
labels; training used the noisy ones.

Outputs: reports/eval_report.md, reports/metrics.json, reports/confusion_matrix.png,
reports/shap_top_features.png

Usage: python -m src.eval.report --config configs/default.yaml
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import matplotlib
import numpy as np
import pandas as pd
from lightgbm import LGBMClassifier
from sklearn.metrics import average_precision_score, confusion_matrix, precision_recall_fscore_support

from src.common.config import load_config, seed_everything
from src.data.io import load_emails, load_sent
from src.data.schema import CATEGORIES, Action, Email
from src.features.extract import ARCHIVE_EXTENSIONS, FEATURES, SUBJECT_FEATURES, merge_stream, model_input
from src.models.train import split_dates
from src.pipeline.cascade import Cascade
from src.services.virus_scan import MACRO_EXTENSIONS, RISKY_EXTENSIONS

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.colors import LinearSegmentedColormap  # noqa: E402

SANDBOX_EXTENSIONS = RISKY_EXTENSIONS | MACRO_EXTENSIONS | ARCHIVE_EXTENSIONS
TEXT_FEATURES = ["text_score", "urgency_kw", "payment_kw", "credential_kw", "topic_shift"]
BLOCKED = {Action.SPAM_FOLDER.value, Action.QUARANTINE.value}
# Chart tokens: one blue hue (sequential ramp) on a light surface, ink for text.
SURFACE, INK, INK_2, GRID, BLUE = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df", "#2a78d6"
BLUES = LinearSegmentedColormap.from_list("blues", ["#f3f7fd", "#9ec5f4", "#3987e5", "#1c5cab", "#0d366b"])


# ---- replay ----------------------------------------------------------------------------
def replay(cfg: dict) -> pd.DataFrame:
    raw = Path(cfg["paths"]["raw"])
    stream = merge_stream(load_emails(raw / "emails.jsonl"), load_sent(raw / "sent.jsonl"))
    _, test_start = split_dates(cfg)
    # Lookups really sleep their simulated latency (so latency is honest wall time); the slow async
    # virus scan stays virtual so the replay does not wait seconds per attachment.
    cas = Cascade.load(cfg, fresh_history=True, simulate_latency=True, simulate_scan_latency=False)
    rows = []
    for e in stream:
        if not isinstance(e, Email):
            cas.observe(e)                                       # sent-mail log
        elif e.timestamp < test_start:
            # Warm-up history before the test period: no verdicts exist, so mail whose observed label is
            # legit stands in for "delivered and not reported" (same proxy as training).
            cas.observe(e, delivered=e.category == "legit")
        else:
            v = cas.classify(e)
            sync_action, sync_cat = v.action.value, v.category
            v, scan_ms = Cascade.remediate(v)
            rows.append({"message_id": e.message_id, "action": sync_action, "pred": sync_cat,
                         "post_action": v.action.value, "post_pred": v.category, "scan_ms": scan_ms,
                         "tier": v.tier, "score": v.score, "latency_ms": v.latency_ms, "cpu_ms": v.cpu_ms,
                         "reasons": "|".join(v.reasons), "n_lookups": 2 + 2 * len({u.href for u in e.urls}),
                         "n_attachments": len(e.attachments),
                         # Sandbox only risky file types, and only if the email is not already quarantined.
                         "n_sandbox": 0 if sync_action == Action.QUARANTINE.value else sum(
                             a.filename.rsplit(".", 1)[-1].lower() in SANDBOX_EXTENSIONS or a.has_macro
                             for a in e.attachments)})
            # Only mail that really reached the inbox (no banner, not pulled by the scan) earns trust.
            cas.observe(e, delivered=v.action == Action.DELIVER)
    return pd.DataFrame(rows)


# ---- metrics helpers ---------------------------------------------------------------------
def binary(y: pd.Series, pred: pd.Series, score: pd.Series | None, df: pd.DataFrame,
           blocked: pd.Series | None = None) -> dict[str, float]:
    """pred = detected (any action but DELIVER); blocked = SPAM_FOLDER / QUARANTINE only (defaults to pred)."""
    p, r, f, _ = precision_recall_fscore_support(y, pred, average="binary", zero_division=0)
    hp, hn = df["scenario"].str.startswith("hard_pos"), df["scenario"].str.startswith("hard_neg")
    bec = df["true_category"] == "bec"
    blocked = pred if blocked is None else blocked
    return {"precision": p, "recall": r, "f1": f,
            "pr_auc": average_precision_score(y, score) if score is not None else np.nan,
            "bec_recall_blocked": blocked[bec].mean(), "bec_recall": pred[bec].mean(),
            "hard_pos_recall": pred[hp].mean(),
            "hard_neg_fp": int(pred[hn].sum()), "legit_fp": int(pred[y == 0].sum())}


def table(df: pd.DataFrame, fmt: dict[str, str] | None = None, index: bool = True) -> str:
    """Markdown table; `fmt` maps column -> format spec (NaN renders as an en dash)."""
    fmt = fmt or {}
    cell = lambda c, v: "–" if pd.isna(v) else format(v, fmt[c]) if c in fmt else str(v)  # noqa: E731
    head = ([""] if index else []) + [str(c) for c in df.columns]
    lines = ["| " + " | ".join(head) + " |", "|" + "|".join(["---"] * len(head)) + "|"]
    for i, row in df.iterrows():
        vals = ([str(i)] if index else []) + [cell(c, row[c]) for c in df.columns]
        lines.append("| " + " | ".join(vals) + " |")
    return "\n".join(lines)


# ---- charts --------------------------------------------------------------------------------
def _style(ax: plt.Axes) -> None:
    ax.set_facecolor(SURFACE)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color(GRID)
    ax.tick_params(colors=INK_2, labelsize=9)


def plot_confusion(cm: np.ndarray, labels: list[str], path: Path) -> None:
    fig, ax = plt.subplots(figsize=(5.6, 4.6), facecolor=SURFACE)
    norm = cm / cm.sum(1, keepdims=True)                    # colour = row share, so small classes read
    ax.imshow(norm, cmap=BLUES, vmin=0, vmax=1)
    for i in range(len(labels)):
        for j in range(len(labels)):
            ax.text(j, i, str(cm[i, j]), ha="center", va="center", fontsize=9,
                    color="#ffffff" if norm[i, j] > 0.55 else INK)
    ax.set_xticks(range(len(labels)), labels)
    ax.set_yticks(range(len(labels)), labels)
    ax.set_xlabel("Predicted (full cascade)", color=INK_2)
    ax.set_ylabel("True class", color=INK_2)
    ax.set_title("Confusion matrix, test period (counts; shade = row share)", color=INK, fontsize=10, loc="left")
    ax.tick_params(colors=INK_2, labelsize=9, length=0)
    for s in ax.spines.values():
        s.set_visible(False)
    fig.tight_layout()
    fig.savefig(path, dpi=150, facecolor=SURFACE)
    plt.close(fig)


def plot_shap(imp: pd.Series, path: Path) -> None:
    imp = imp.sort_values()
    fig, ax = plt.subplots(figsize=(6.4, 4.8), facecolor=SURFACE)
    ax.barh(imp.index, imp.values, color=BLUE, height=0.6)
    _style(ax)
    ax.xaxis.grid(True, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    ax.set_xlabel("mean |SHAP value| (summed over classes)", color=INK_2)
    ax.set_title("Top features driving LightGBM", color=INK, fontsize=10, loc="left")
    fig.tight_layout()
    fig.savefig(path, dpi=150, facecolor=SURFACE)
    plt.close(fig)


def shap_importance(model: LGBMClassifier, X: pd.DataFrame, top: int = 15) -> pd.Series:
    import shap

    sv = shap.TreeExplainer(model).shap_values(X)
    arr = np.stack(sv, axis=-1) if isinstance(sv, list) else np.asarray(sv)   # (n, features, classes)
    return pd.Series(np.abs(arr).mean(0).sum(-1), index=X.columns).nlargest(top)


def text_terms(text_model: dict, n: int = 15) -> pd.DataFrame:
    """Words / phrases with the largest logistic-regression weights in each direction."""
    names = text_model["vectorizer"].get_feature_names_out()
    coef = text_model["lr"].coef_[0]
    order = np.argsort(coef)
    return pd.DataFrame({"toward attack": [f"{names[i]} ({coef[i]:+.2f})" for i in order[::-1][:n]],
                         "toward legit": [f"{names[i]} ({coef[i]:+.2f})" for i in order[:n]]},
                        index=range(1, n + 1))


# ---- cost ----------------------------------------------------------------------------------
def cost_per_mailbox(cfg: dict, res: pd.DataFrame, cpu_ms: float, emails_per_day: float,
                     proposed: bool) -> pd.Series:
    """Estimated variable $ per mailbox per month at a given inbound volume, reusing per-email rates
    observed in the replay. proposed=False is what is implemented (every lookup paid, every attachment
    through the single scanner); proposed=True adds the lookup cache, hash cache and AV + selective sandbox."""
    c = cfg["cost"]
    per_month = emails_per_day * 30
    compute = per_month * cpu_ms * c["cpu_overhead"] / 3.6e6 * c["vcpu_hour_usd"]
    if proposed:
        lookups = per_month * res["n_lookups"].mean() * (1 - c["lookup_cache_hit"]) * c["lookup_usd"]
        miss = 1 - c["scan_cache_hit"]
        scanning = per_month * miss * (res["n_attachments"].mean() * c["av_usd"]
                                       + res["n_sandbox"].mean() * c["sandbox_usd"])
    else:
        lookups = per_month * res["n_lookups"].mean() * c["lookup_usd"]
        scanning = per_month * res["n_attachments"].mean() * c["sandbox_usd"]
    items = pd.Series({"Compute (features, rules, models)": compute, "Reputation / WHOIS lookups": lookups,
                       "Attachment scanning": scanning})
    items["**Total**"] = items.sum()
    return items


def cost_estimate(cfg: dict, res: pd.DataFrame, cpu_ms: float) -> pd.DataFrame:
    """Base case and projection, each as implemented and with the proposed savings ($/mailbox/month)."""
    c = cfg["cost"]
    cols = {}
    for vol, key in (("base", "emails_per_mailbox_day"), ("projection", "projection_emails_per_mailbox_day")):
        for name, proposed in (("as implemented", False), ("with proposed savings", True)):
            cols[f"{vol} ({c[key]}/day), {name}"] = cost_per_mailbox(cfg, res, cpu_ms, c[key], proposed)
    out = pd.DataFrame(cols)
    out.loc["Share of budget"] = out.loc["**Total**"] / c["budget_per_mailbox_month"]
    return out


# ---- main ----------------------------------------------------------------------------------
def run(cfg: dict) -> dict:
    """Evaluate one trained config, write its reports/ and return the metrics dict."""
    seed = cfg["seed"]
    seed_everything(seed)
    out_dir = Path(cfg["paths"]["reports"])
    out_dir.mkdir(parents=True, exist_ok=True)

    feats = pd.read_parquet(Path(cfg["paths"]["processed"]) / "features.parquet")
    lgbm = joblib.load(Path(cfg["paths"]["models"]) / "lgbm.joblib")
    res = replay(cfg)
    df = feats.merge(res, on="message_id")
    y = df["true_label"]
    fill = json.loads((Path(cfg["paths"]["models"]) / "feature_fill.json").read_text())
    X = model_input(df, fill)
    proba = lgbm.predict_proba(X)
    df["model_score"] = 1 - proba[:, 0]
    modelled = df["tier"].isin([1, 2])                   # Tier 0 and fail-open verdicts never ran the model
    assert np.allclose(df.loc[modelled, "model_score"], df.loc[modelled, "score"], atol=1e-6), \
        "replayed features differ from training table"

    # Ablation: same test rows, same true labels.
    train_start, _ = split_dates(cfg)
    fit = feats[(feats["split"] == "train") & (feats["timestamp"] >= train_start)]
    X_fit = model_input(fit, fill)
    def ablation_score(cols: list[str]) -> pd.Series:
        """Retrain LightGBM (same params, same rows) on a feature subset; P(malicious) on test."""
        m = LGBMClassifier(objective="multiclass", **cfg["model"]["lgbm"], random_state=seed, verbose=-1)
        m.fit(X_fit[cols], fit["category"].map({c: i for i, c in enumerate(CATEGORIES)}))
        return pd.Series(1 - m.predict_proba(X[cols])[:, 0], index=df.index)

    meta_score = ablation_score([f for f in FEATURES if f not in TEXT_FEATURES + SUBJECT_FEATURES])
    nosubj_score = ablation_score([f for f in FEATURES if f not in SUBJECT_FEATURES])
    n_rules = df["rules"].str.split("|").map(lambda r: len([x for x in r if x]))
    no_t2 = df["action"].where(df["tier"] != 2, Action.WARNING_BANNER.value)
    ablation = pd.DataFrame({
        "Rules only (Tier 0 block)": binary(y, df["rule_block"].astype(int), n_rules, df),
        "Text only (TF-IDF + LR)": binary(y, (df["text_score"] >= 0.5).astype(int), df["text_score"], df),
        "Metadata only (no text or subject features)": binary(y, (meta_score >= 0.5).astype(int), meta_score, df),
        "Full model (LightGBM, no subject features)": binary(y, (nosubj_score >= 0.5).astype(int), nosubj_score, df),
        "Full model + subject features": binary(y, (df["model_score"] >= 0.5).astype(int), df["model_score"], df),
        # Same rules and thresholds; the gray zone gets a banner instead of the intent check.
        "Cascade without intent check": binary(y, (no_t2 != "DELIVER").astype(int), None, df,
                                                no_t2.isin(BLOCKED).astype(int)),
        "Full cascade": binary(y, (df["action"] != "DELIVER").astype(int), None, df,
                               df["action"].isin(BLOCKED).astype(int)),
        "Full cascade + async virus scan": binary(y, (df["post_action"] != "DELIVER").astype(int), None, df,
                                                  df["post_action"].isin(BLOCKED).astype(int)),
    }).T

    # Per-class: final output (post-scan). Banner counts as a detection of its predicted class.
    pred = np.where(df["post_action"] == "DELIVER", "legit", df["post_pred"])
    p, r, f, s = precision_recall_fscore_support(df["true_category"], pred, labels=list(CATEGORIES), zero_division=0)
    per_class = pd.DataFrame({"precision": p, "recall": r, "f1": f, "support": s,
                              "pr_auc (LightGBM)": [average_precision_score(df["true_category"] == c, proba[:, i])
                                                   for i, c in enumerate(CATEGORIES)]}, index=list(CATEGORIES))
    cm = confusion_matrix(df["true_category"], pred, labels=list(CATEGORIES))
    actions = pd.crosstab(df["true_category"], df["post_action"]).reindex(
        index=list(CATEGORIES), columns=[a.value for a in Action], fill_value=0)

    hard = df[df["scenario"].str.startswith("hard_")]
    hard_tbl = hard.groupby("scenario").agg(
        n=("message_id", "size"), blocked=("post_action", lambda a: a.isin(BLOCKED).sum()),
        banner=("post_action", lambda a: (a == "WARNING_BANNER").sum()),
        delivered=("post_action", lambda a: (a == "DELIVER").sum()))
    bec = df[df["true_category"] == "bec"].groupby("scenario")["post_action"].value_counts().unstack(fill_value=0)

    # Latency (sync path only; the virus scan is async) and cost.
    lat = df["latency_ms"]
    cpu_ms = float(df["cpu_ms"].mean())
    latency = pd.DataFrame({"p50": [lat.quantile(0.5)], "p95": [lat.quantile(0.95)], "p99": [lat.quantile(0.99)],
                            "max": [lat.max()]}, index=["wall time, ms"])
    tiers = df["tier"].value_counts(normalize=True).sort_index()
    n_fail_open = int((df["tier"] == -1).sum())
    scans = df["scan_ms"].dropna()
    cost = cost_estimate(cfg, df, cpu_ms)
    c = cfg["cost"]
    totals = cost.loc["**Total**"]
    base_impl, base_prop, proj_impl, proj_prop = (float(v) for v in totals.values)
    d = cfg["data"]
    synthetic_rate = d["n_emails"] / (d["n_tenants"] * d["mailboxes_per_tenant"] * d["days"])
    headroom = c["budget_per_mailbox_month"] - base_impl
    gray_per_month = c["emails_per_mailbox_day"] * 30 * tiers.get(2, 0)
    per_gray_email = headroom / gray_per_month if gray_per_month else float("nan")

    imp = shap_importance(lgbm, X)
    terms = text_terms(joblib.load(Path(cfg["paths"]["models"]) / "text_model.joblib"))
    plot_confusion(cm, list(CATEGORIES), out_dir / "confusion_matrix.png")
    plot_shap(imp, out_dir / "shap_top_features.png")

    pct = {c: ".1%" for c in ["precision", "recall", "f1", "bec_recall_blocked", "bec_recall", "hard_pos_recall"]}
    report = f"""# Evaluation report

Test period: last {cfg['data']['test_days']} days ({len(df)} emails, {int(y.sum())} malicious). Metrics use true
labels; models were trained on labels with {cfg['data']['label_noise']:.0%} noise. Generated by `make eval`.

## Ablation

Binary task: malicious vs legit. Thresholds: 0.5 for scores; for the cascade a detection is any action
other than DELIVER. BEC recall is shown twice: `bec_recall_blocked` counts only SPAM_FOLDER / QUARANTINE,
`bec_recall` also counts WARNING_BANNER (for score rows they are equal). "Cascade without intent check"
uses the same rules and thresholds but banners every gray-zone email. PR-AUC needs a score, so it is
blank for the cascade rows. Hard negatives in test: {int(df['scenario'].str.startswith('hard_neg').sum())}.

{table(ablation, pct | {"pr_auc": ".3f", "hard_neg_fp": ".0f", "legit_fp": ".0f"})}

## Per-class results (full cascade + async scan)

{table(per_class, {"precision": ".1%", "recall": ".1%", "f1": ".1%", "support": ".0f", "pr_auc (LightGBM)": ".3f"})}

**BEC** is the class that matters most and is hardest: no links, no attachments to scan, often sent from a
real or freemail account. BEC actions by scenario:

{table(bec)}

### Actions per true class

{table(actions)}

![Confusion matrix](confusion_matrix.png)

## Hard cases

Hard positives are attacks from real, trusted accounts or with copied legit wording; hard negatives
are legit mail that looks risky. Recall on hard positives (any action but DELIVER):
**{ablation.loc['Full cascade + async virus scan', 'hard_pos_recall']:.1%}**. Hard negatives
blocked: **{int(hard_tbl.loc[hard_tbl.index.str.startswith('hard_neg'), 'blocked'].sum())}**,
bannered: **{int(hard_tbl.loc[hard_tbl.index.str.startswith('hard_neg'), 'banner'].sum())}**.

{table(hard_tbl)}

## What drives the model (SHAP)

![SHAP top features](shap_top_features.png)

{table(imp.rename("mean |SHAP|").to_frame(), {"mean |SHAP|": ".3f"})}

### What the text model learned

Top TF-IDF terms by logistic-regression weight (URLs, sender display names and the recipient's name are
masked before vectorising; bigrams never cross a sentence boundary).

{table(terms)}

## Latency

Wall time of the synchronous path per email, measured once: the mock WHOIS / IP / URL lookups really
sleep their simulated latency and run concurrently (each with its own timeout) under the shared
{cfg['cascade']['sync_deadline_ms']} ms deadline; past it the verdict is DELIVER (fail open). Mean CPU time:
{cpu_ms:.1f} ms per email. Target: p99 under {cfg['cascade']['target_p99_ms']} ms. Fail-open (deadline) verdicts in this run:
{n_fail_open}.

{table(latency, {c: ".1f" for c in latency.columns})}

Decided at Tier 0 (before any model runs): {tiers.get(0, 0):.1%}, Tier 1: {tiers.get(1, 0):.1%}, Tier 2 (gray zone):
{tiers.get(2, 0):.1%}.
The virus scan runs asynchronously; it pulled {len(scans)} delivered emails after the fact{
f" (median {scans.median():.0f} ms after arrival)" if len(scans) else
": everything it detected had already been quarantined by the synchronous path"}.

## Estimated variable cost vs the ${c['budget_per_mailbox_month']:.2f}/mailbox/month budget

An estimate of variable cost under stated deployment assumptions (configs/default.yaml), not a
measurement. **As implemented**, every lookup is a paid call and every attachment goes through the
single scanner (priced as a sandbox, ${c['sandbox_usd']}). **With proposed savings** (not implemented): a
{c['lookup_cache_hit']:.0%}-hit lookup cache, a {c['scan_cache_hit']:.0%}-hit attachment hash cache, a cheap static AV scan
(${c['av_usd']:.5f}) on every file and the sandbox only for archives, macro documents and executables on
mail that was not already quarantined.

The synthetic data has ~{synthetic_rate:.2f} emails per mailbox per day. The **base case** uses the specified
{c['emails_per_mailbox_day']}/day; the **projection** uses {c['projection_emails_per_mailbox_day']}/day (a heavy inbox). Both reuse the per-email rates observed in
this replay: {df['n_lookups'].mean():.1f} lookups, {df['n_attachments'].mean():.2f} attachments, {df['n_sandbox'].mean():.3f} sandbox submissions and
{cpu_ms:.1f} ms CPU per email (×{c['cpu_overhead']} overhead at ${c['vcpu_hour_usd']}/vCPU-hour).

{table(cost, {k: ".4f" for k in cost.columns})}

(The last row is the share of the ${c['budget_per_mailbox_month']:.2f} budget.) **Headroom for a smarter Tier 2**, base case as
implemented: ${headroom:.2f}/mailbox/month; with {tiers.get(2, 0):.1%} of mail in the gray zone that is
{gray_per_month:.1f} emails per mailbox per month, so up to **${per_gray_email:.2f} per gray-zone email** for embeddings
or an LLM call.
"""
    (out_dir / "eval_report.md").write_text(report)
    metrics = {"ablation": ablation.to_dict(orient="index"), "per_class": per_class.to_dict(orient="index"),
               "latency_ms": latency.iloc[0].to_dict(), "tier_share": tiers.to_dict(),
               "cost_per_mailbox_month": {"base_implemented": base_impl, "base_proposed": base_prop,
                                          "projection_implemented": proj_impl, "projection_proposed": proj_prop},
               "fail_open": n_fail_open, "cpu_ms": cpu_ms,
               "tier2_headroom": {"usd_per_mailbox_month": headroom, "usd_per_gray_zone_email": per_gray_email},
               "shap_top": imp.to_dict(), "text_terms": terms.to_dict(orient="list")}
    (out_dir / "metrics.json").write_text(json.dumps(metrics, indent=1, default=float))
    print(table(ablation, pct | {"pr_auc": ".3f", "hard_neg_fp": ".0f", "legit_fp": ".0f"}))
    print()
    print(table(per_class, {"precision": ".1%", "recall": ".1%", "f1": ".1%", "pr_auc (LightGBM)": ".3f"}))
    print()
    print(table(latency, {c: ".1f" for c in latency.columns}))
    print(f"tiers: {tiers.round(3).to_dict()}  fail-open: {n_fail_open}  cost/mailbox/month base "
          f"${base_impl:.4f} (implemented) / ${base_prop:.4f} (proposed), projection ${proj_impl:.4f} / "
          f"${proj_prop:.4f}; Tier 2 headroom ${per_gray_email:.2f} per gray-zone email")
    print(f"wrote {out_dir}/eval_report.md")
    return metrics


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--config", default=None)
    run(load_config(ap.parse_args().config))


if __name__ == "__main__":
    main()
