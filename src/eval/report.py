"""Evaluate the cascade on the held-out period and write reports/.

The cascade is replayed over the real stream: train-period emails only build sender
history, then every test email is classified live (features, rules, models, intent check,
virus scan) and added to history afterwards. All metrics use the *true* labels; training
used the noisy ones.

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
from src.data.io import load_emails
from src.data.schema import CATEGORIES, Action
from src.features.extract import ARCHIVE_EXTENSIONS, FEATURES
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
    emails = load_emails(Path(cfg["paths"]["raw"]) / "emails.jsonl")
    _, test_start = split_dates(cfg)
    cas = Cascade.load(cfg, fresh_history=True)
    rows = []
    for e in emails:
        if e.timestamp >= test_start:
            v = cas.classify(e)
            sync_action, sync_cat = v.action.value, v.category
            v, scan_ms = Cascade.remediate(v)
            rows.append({"message_id": e.message_id, "action": sync_action, "pred": sync_cat,
                         "post_action": v.action.value, "post_pred": v.category, "scan_ms": scan_ms,
                         "tier": v.tier, "score": v.score, "latency_ms": v.latency_ms,
                         "reasons": "|".join(v.reasons), "n_lookups": 2 + 2 * len({u.href for u in e.urls}),
                         "n_attachments": len(e.attachments),
                         # Sandbox only risky file types, and only if the email is not already quarantined.
                         "n_sandbox": 0 if sync_action == Action.QUARANTINE.value else sum(
                             a.filename.rsplit(".", 1)[-1].lower() in SANDBOX_EXTENSIONS or a.has_macro
                             for a in e.attachments)})
        cas.observe(e)
    return pd.DataFrame(rows)


# ---- metrics helpers ---------------------------------------------------------------------
def binary(y: pd.Series, pred: pd.Series, score: pd.Series | None, df: pd.DataFrame) -> dict[str, float]:
    p, r, f, _ = precision_recall_fscore_support(y, pred, average="binary", zero_division=0)
    hp, hn = df["scenario"].str.startswith("hard_pos"), df["scenario"].str.startswith("hard_neg")
    bec = df["true_category"] == "bec"
    return {"precision": p, "recall": r, "f1": f,
            "pr_auc": average_precision_score(y, score) if score is not None else np.nan,
            "bec_recall": pred[bec].mean(), "hard_pos_recall": pred[hp].mean(),
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
def cost_per_mailbox(cfg: dict, res: pd.DataFrame, compute_ms: float, emails_per_day: float) -> pd.Series:
    """Monthly $ per mailbox by item at a given inbound volume."""
    c = cfg["cost"]
    per_month = emails_per_day * 30
    compute = per_month * compute_ms * c["cpu_overhead"] / 3.6e6 * c["vcpu_hour_usd"]
    lookups = per_month * res["n_lookups"].mean() * (1 - c["lookup_cache_hit"]) * c["lookup_usd"]
    miss = 1 - c["scan_cache_hit"]
    av = per_month * res["n_attachments"].mean() * miss * c["av_usd"]
    sandbox = per_month * res["n_sandbox"].mean() * miss * c["sandbox_usd"]
    items = pd.Series({"Compute (features, rules, models)": compute, "Reputation / WHOIS lookups": lookups,
                       "Static AV scan (every attachment)": av, "Sandbox (risky types, not quarantined)": sandbox})
    items["**Total**"] = items.sum()
    return items


def cost_estimate(cfg: dict, res: pd.DataFrame, compute_ms: float) -> pd.DataFrame:
    """Base case (assignment volume) and stress test side by side, in $ and share of budget."""
    c = cfg["cost"]
    out = pd.DataFrame(index=cost_per_mailbox(cfg, res, compute_ms, 1).index)
    for name, key in (("base", "emails_per_mailbox_day"), ("stress", "stress_emails_per_mailbox_day")):
        usd = cost_per_mailbox(cfg, res, compute_ms, c[key])
        out[f"{name}: $/mailbox/month"] = usd
        out[f"{name}: share of budget"] = usd / c["budget_per_mailbox_month"]
    return out


# ---- main ----------------------------------------------------------------------------------
def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--config", default=None)
    cfg = load_config(ap.parse_args().config)
    seed = cfg["seed"]
    seed_everything(seed)
    out_dir = Path(cfg["paths"]["reports"])
    out_dir.mkdir(parents=True, exist_ok=True)

    feats = pd.read_parquet(Path(cfg["paths"]["processed"]) / "features.parquet")
    lgbm = joblib.load(Path(cfg["paths"]["models"]) / "lgbm.joblib")
    res = replay(cfg)
    df = feats.merge(res, on="message_id")
    y = df["true_label"]
    proba = lgbm.predict_proba(df[FEATURES])
    df["model_score"] = 1 - proba[:, 0]
    assert np.allclose(df["model_score"], df["score"], atol=1e-6), "replayed features differ from training table"

    # Ablation: same test rows, same true labels.
    train_start, _ = split_dates(cfg)
    fit = feats[(feats["split"] == "train") & (feats["timestamp"] >= train_start)]
    meta_cols = [f for f in FEATURES if f not in TEXT_FEATURES]
    meta = LGBMClassifier(objective="multiclass", **cfg["model"]["lgbm"], random_state=seed, verbose=-1)
    meta.fit(fit[meta_cols], fit["category"].map({c: i for i, c in enumerate(CATEGORIES)}))
    meta_score = pd.Series(1 - meta.predict_proba(df[meta_cols])[:, 0], index=df.index)
    n_rules = df["rules"].str.split("|").map(lambda r: len([x for x in r if x]))
    ablation = pd.DataFrame({
        "Rules only (Tier 0 block)": binary(y, df["rule_block"].astype(int), n_rules, df),
        "Text only (TF-IDF + LR)": binary(y, (df["text_score"] >= 0.5).astype(int), df["text_score"], df),
        "Metadata only (no text features)": binary(y, (meta_score >= 0.5).astype(int), meta_score, df),
        "Full model (LightGBM)": binary(y, (df["model_score"] >= 0.5).astype(int), df["model_score"], df),
        "Full cascade (blocked)": binary(y, df["action"].isin(BLOCKED).astype(int), None, df),
        "Full cascade (blocked or banner)": binary(y, (df["action"] != "DELIVER").astype(int), None, df),
        "Full cascade + async virus scan": binary(y, (df["post_action"] != "DELIVER").astype(int), None, df),
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
    compute_ms = float(lat.mean() - df["svc_latency_ms"].mean())
    latency = pd.DataFrame({"p50": [lat.quantile(0.5)], "p95": [lat.quantile(0.95)], "p99": [lat.quantile(0.99)],
                            "max": [lat.max()]}, index=["end-to-end ms"])
    tiers = df["tier"].value_counts(normalize=True).sort_index()
    scans = df["scan_ms"].dropna()
    cost = cost_estimate(cfg, df, compute_ms)
    c = cfg["cost"]
    base_total = float(cost["base: $/mailbox/month"].iloc[-1])
    stress_total = float(cost["stress: $/mailbox/month"].iloc[-1])
    headroom = c["budget_per_mailbox_month"] - base_total
    gray_per_month = c["emails_per_mailbox_day"] * 30 * tiers.get(2, 0)
    per_gray_email = headroom / gray_per_month if gray_per_month else float("nan")

    imp = shap_importance(lgbm, df[FEATURES])
    terms = text_terms(joblib.load(Path(cfg["paths"]["models"]) / "text_model.joblib"))
    plot_confusion(cm, list(CATEGORIES), out_dir / "confusion_matrix.png")
    plot_shap(imp, out_dir / "shap_top_features.png")

    pct = {c: ".1%" for c in ["precision", "recall", "f1", "bec_recall", "hard_pos_recall"]}
    report = f"""# Evaluation report

Test period: last {cfg['data']['test_days']} days ({len(df)} emails, {int(y.sum())} malicious). Metrics use true
labels; models were trained on labels with {cfg['data']['label_noise']:.0%} noise. Generated by `make eval`.

## Ablation

Binary task: malicious vs legit. Thresholds: 0.5 for scores; for the cascade a detection is an action
other than DELIVER (or only SPAM_FOLDER / QUARANTINE for "blocked"). PR-AUC needs a score, so it is
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

End-to-end synchronous latency per email: measured compute (features, rules, both models, intent
check) plus the simulated external lookups, which fan out in parallel (so the slowest one counts).
Mean compute alone: {compute_ms:.1f} ms. Budget: p99 under {cfg['cascade']['target_p99_ms']} ms; provider
deadline {cfg['cascade']['sync_deadline_ms']} ms.

{table(latency, {c: ".1f" for c in latency.columns})}

Decided at Tier 0: {tiers.get(0, 0):.1%}, Tier 1: {tiers.get(1, 0):.1%}, Tier 2 (gray zone): {tiers.get(2, 0):.1%}.
The virus scan runs asynchronously; it pulled {len(scans)} delivered emails after the fact{
f" (median {scans.median():.0f} ms after arrival)" if len(scans) else
": everything it detected had already been quarantined by the synchronous path"}.

## Cost vs the ${c['budget_per_mailbox_month']:.2f}/mailbox/month budget

**Base case** ({c['emails_per_mailbox_day']} inbound emails per mailbox per day, as specified):
**${base_total:.4f}/mailbox/month ({base_total / c['budget_per_mailbox_month']:.1%} of budget)**.
**Stress test** ({c['stress_emails_per_mailbox_day']}/day): ${stress_total:.4f} ({stress_total / c['budget_per_mailbox_month']:.1%}),
{"still within" if stress_total <= c['budget_per_mailbox_month'] else "over"} budget.

**Headroom for a smarter Tier 2:** the base case leaves ${headroom:.2f}/mailbox/month. With
{tiers.get(2, 0):.1%} of mail in the gray zone that is {gray_per_month:.1f} emails per mailbox per month, so up to
**${per_gray_email:.2f} per gray-zone email** could go to embeddings or an LLM call and still fit the budget.

Other assumptions (configs/default.yaml):
${cfg['cost']['vcpu_hour_usd']}/vCPU-hour with a {cfg['cost']['cpu_overhead']}x overhead on measured compute,
{cfg['cost']['lookup_cache_hit']:.0%} cache hits on lookups at ${cfg['cost']['lookup_usd']} each, and
{cfg['cost']['scan_cache_hit']:.0%} hash-cache hits on attachments. Every attachment gets a self-hosted static AV
scan (${cfg['cost']['av_usd']:.5f}); only archives, macro documents and executables / disk images go to the
sandbox (${cfg['cost']['sandbox_usd']}), and only when the email was not already quarantined. Measured on this run:
{df['n_lookups'].mean():.1f} lookups, {df['n_attachments'].mean():.2f} attachments and
{df['n_sandbox'].mean():.3f} sandbox submissions per email.

{table(cost, {k: (".4f" if "$" in k else ".1%") for k in cost.columns})}
"""
    (out_dir / "eval_report.md").write_text(report)
    metrics = {"ablation": ablation.to_dict(orient="index"), "per_class": per_class.to_dict(orient="index"),
               "latency_ms": latency.iloc[0].to_dict(), "tier_share": tiers.to_dict(),
               "cost_per_mailbox_month": {"base": base_total, "stress": stress_total},
               "tier2_headroom": {"usd_per_mailbox_month": headroom, "usd_per_gray_zone_email": per_gray_email},
               "shap_top": imp.to_dict(), "text_terms": terms.to_dict(orient="list")}
    (out_dir / "metrics.json").write_text(json.dumps(metrics, indent=1, default=float))
    print(table(ablation, pct | {"pr_auc": ".3f", "hard_neg_fp": ".0f", "legit_fp": ".0f"}))
    print()
    print(table(per_class, {"precision": ".1%", "recall": ".1%", "f1": ".1%", "pr_auc (LightGBM)": ".3f"}))
    print()
    print(table(latency, {c: ".1f" for c in latency.columns}))
    print(f"tiers: {tiers.round(3).to_dict()}  cost/mailbox/month: base ${base_total:.4f}, "
          f"stress ${stress_total:.4f}; Tier 2 headroom ${per_gray_email:.2f} per gray-zone email")
    print(f"wrote {out_dir}/eval_report.md")


if __name__ == "__main__":
    main()
