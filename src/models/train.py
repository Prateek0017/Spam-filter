"""Build point-in-time features, train the text model and LightGBM, save everything.

Steps
  1. Time split: train = before (end - test_days), test = after. The first `warmup_days`
     only build sender history (every sender is "new" then) and are not trained on.
  2. Fit TF-IDF on train text only.
  3. Walk the whole stream in time order: extract features, then update history.
  4. Text LR: out-of-fold scores on train, full-train fit scores test -> `text_score`.
  5. LightGBM multiclass on the observed (noisy) labels.
  6. Tier 2 intent model (weakly supervised) on train text.

Usage: python -m src.models.train --config configs/default.yaml
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from lightgbm import LGBMClassifier
from sklearn.metrics import average_precision_score, f1_score

from src.common.config import load_config, seed_everything
from src.data.io import load_emails, load_sent, load_tenants
from src.data.schema import CATEGORIES, SentMessage
from src.features.extract import FEATURES, FeatureExtractor, email_text, merge_stream
from src.models.text import make_lr, make_vectorizer, oof_scores
from src.pipeline.intent import IntentModel
from src.rules.engine import RULES, blocks, run_rules
from src.services import build_services


def split_dates(cfg: dict) -> tuple[datetime, datetime]:
    """(start of training period, start of test period)."""
    d = cfg["data"]
    start = datetime.fromisoformat(str(d["start_date"]))
    return start + timedelta(days=cfg["model"]["warmup_days"]), start + timedelta(days=d["days"] - d["test_days"])


def build_feature_table(cfg: dict) -> tuple[pd.DataFrame, FeatureExtractor, object, list[str]]:
    raw = Path(cfg["paths"]["raw"])
    emails, tenants = load_emails(raw / "emails.jsonl"), load_tenants(raw / "tenants.json")
    sent = load_sent(raw / "sent.jsonl")
    _, test_start = split_dates(cfg)
    texts = [email_text(e) for e in emails]
    vectorizer = make_vectorizer().fit([t for t, e in zip(texts, emails) if e.timestamp < test_start])
    X_text = vectorizer.transform(texts)

    fx = FeatureExtractor(tenants, build_services(cfg), vectorizer)
    models = Path(cfg["paths"]["models"])
    models.mkdir(parents=True, exist_ok=True)
    rows, snapshot_saved = [], False
    index = {id(e): i for i, e in enumerate(emails)}
    for item in merge_stream(emails, sent):
        if isinstance(item, SentMessage):
            fx.record_sent(item)
            continue
        e, i = item, index[id(item)]
        if not snapshot_saved and e.timestamp >= test_start:
            # Sender history as of the split: the demo classifies test emails as unseen mail.
            joblib.dump(fx, models / "feature_extractor.joblib")
            snapshot_saved = True
        feats, svc_ms = fx.extract(e, X_text[i])
        hits = run_rules(feats)
        rows.append({
            "message_id": e.message_id, "tenant_id": e.tenant_id, "timestamp": e.timestamp,
            "category": e.category, "true_category": e.true_category, "label": e.label,
            "true_label": int(e.true_category != "legit"), "scenario": e.scenario,
            **feats, "svc_latency_ms": svc_ms,
            "rules": "|".join(r.code for r in hits), "rule_block": blocks(hits, feats),
        })
        fx.update(e, X_text[i])
    df = pd.DataFrame(rows)
    df["split"] = np.where(df["timestamp"] >= test_start, "test", "train")
    return df, fx, X_text, texts


def rule_report(df: pd.DataFrame) -> pd.DataFrame:
    """Per-rule fire count and precision against true labels (used to pick block vs flag)."""
    out = []
    for r in RULES:
        hit = df["rules"].str.contains(rf"\b{r.code}\b")
        out.append({"rule": r.code, "severity": r.severity, "fires": int(hit.sum()),
                    "precision": df.loc[hit, "true_label"].mean() if hit.any() else np.nan,
                    "recall": hit[df["true_label"] == 1].mean()})
    b = df["rule_block"]
    out.append({"rule": "=> Tier 0 block", "severity": "", "fires": int(b.sum()),
                "precision": df.loc[b, "true_label"].mean(), "recall": b[df["true_label"] == 1].mean()})
    return pd.DataFrame(out)


def run(cfg: dict) -> None:
    """Train everything for one config (paths and seed come from cfg)."""
    seed = cfg["seed"]
    seed_everything(seed)
    train_start, _ = split_dates(cfg)

    df, fx, X_text, texts = build_feature_table(cfg)
    tr = (df["split"] == "train").to_numpy()
    fit = tr & (df["timestamp"] >= train_start).to_numpy()

    # Text model: OOF on train rows, model fit on all train rows scores the test rows.
    y_bin = df["label"].to_numpy()
    text_lr = make_lr(seed).fit(X_text[tr], y_bin[tr])
    df["text_score"] = 0.0
    df.loc[tr, "text_score"] = oof_scores(X_text[tr], y_bin[tr], seed)
    df.loc[~tr, "text_score"] = text_lr.predict_proba(X_text[~tr])[:, 1]

    y = df["category"].map({c: i for i, c in enumerate(CATEGORIES)}).to_numpy()
    model = LGBMClassifier(objective="multiclass", **cfg["model"]["lgbm"], random_state=seed, verbose=-1)
    model.fit(df.loc[fit, FEATURES], y[fit])

    intent = IntentModel(seed).fit(X_text[tr], [t for t, keep in zip(texts, tr) if keep])

    models, processed = Path(cfg["paths"]["models"]), Path(cfg["paths"]["processed"])
    processed.mkdir(parents=True, exist_ok=True)
    joblib.dump({"vectorizer": fx.vectorizer, "lr": text_lr}, models / "text_model.joblib")
    joblib.dump(model, models / "lgbm.joblib")
    joblib.dump(intent, models / "intent.joblib")
    df.to_parquet(processed / "features.parquet", index=False)

    # Sanity check on the held-out period, against true labels (full report: make eval).
    te = df[~tr]
    proba = model.predict_proba(te[FEATURES])
    pred = np.array(CATEGORIES)[proba.argmax(1)]
    print(f"train rows {fit.sum()} (after {cfg['model']['warmup_days']}-day warm-up), test rows {len(te)}")
    print(f"test PR-AUC malicious-vs-legit: {average_precision_score(te['true_label'], 1 - proba[:, 0]):.3f}  "
          f"text-only: {average_precision_score(te['true_label'], te['text_score']):.3f}")
    print(f"test macro-F1 (5 classes): {f1_score(te['true_category'], pred, average='macro'):.3f}")
    print("\nTier 0 rules on the training period (precision vs true labels):")
    print(rule_report(df[tr]).to_string(index=False, float_format="%.3f"))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--config", default=None)
    run(load_config(ap.parse_args().config))


if __name__ == "__main__":
    main()
