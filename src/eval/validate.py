"""Reproducible model selection on a validation window, then a refit on the full training period.

  1. Validation window = the last `validation_days` of the training period. Everything (TF-IDF
     vocabulary, text model, intent model, missing-value medians, LightGBM) is fitted only on
     data before the window.
  2. Sweep LightGBM settings; pick the best validation PR-AUC (observed labels, which is all a real
     deployment has).
  3. With that model, sweep the gray-zone lower bound: replay the Tier 0 / 1 / 2 decisions on the
     window and pick the bound that catches the most hard positives while bannering or blocking at
     most `banner_budget` of legit mail.
  4. If the choices match configs/default.yaml, refit everything on the full training period
     (exactly `make train`); otherwise stop and say what to change.

Output: reports/validation.md
Usage: python -m src.eval.validate --config configs/default.yaml
"""
from __future__ import annotations

import argparse
from datetime import timedelta
from pathlib import Path

import numpy as np
import pandas as pd
from lightgbm import LGBMClassifier
from sklearn.metrics import average_precision_score

from src.common.config import load_config, seed_everything
from src.data.schema import CATEGORIES
from src.eval.report import table
from src.features.extract import FEATURES, model_input
from src.models import train
from src.models.text import make_lr, oof_scores
from src.pipeline.intent import RISKY_INTENTS, IntentModel

BASE = {"learning_rate": 0.05, "num_leaves": 15, "subsample": 0.8, "subsample_freq": 1, "colsample_bytree": 0.8}
SHOWN = ["n_estimators", "num_leaves", "min_child_samples", "reg_lambda"]
GRID = [
    {"n_estimators": 300, "min_child_samples": 20, "reg_lambda": 0.0},
    {"n_estimators": 150, "min_child_samples": 20, "reg_lambda": 0.0},
    {"n_estimators": 300, "num_leaves": 7, "min_child_samples": 40, "reg_lambda": 0.0},
    {"n_estimators": 300, "min_child_samples": 40, "reg_lambda": 5.0},
    {"n_estimators": 150, "min_child_samples": 40, "reg_lambda": 5.0},
]
LOWER_BOUNDS = [0.30, 0.20, 0.10, 0.05]


def gray_zone_sweep(cfg: dict, va: pd.DataFrame, score: np.ndarray, intents: list[dict]) -> pd.DataFrame:
    """Replay the cascade's decisions on the validation rows for each candidate lower bound."""
    c = cfg["cascade"]
    hi = c["gray_zone"][1]
    asks = np.array([any(d[k] >= c["intent_min"] for k in RISKY_INTENTS) for d in intents])
    spoofable = (va["dmarc_fail"] == 1).to_numpy()            # failing DMARC inherits no trust
    untrusted = spoofable | ((va["sent_to_sender"] == 0) & (va["delivered_prior"] == 0)).to_numpy()
    established = ~spoofable & ((va["sent_to_sender"] > 0)
                                | (va["delivered_prior"] >= c["established_min_msgs"])).to_numpy()
    off = (untrusted | (va["topic_shift"] >= c["topic_shift_high"]).to_numpy()
           | (va["reply_to_mismatch"] == 1).to_numpy() | (va["display_name_mismatch"] == 1).to_numpy())
    tier0 = va["rule_block"].to_numpy(dtype=bool)
    y = va["label"].to_numpy() == 1
    hard_pos = va["scenario"].str.startswith("hard_pos").to_numpy()
    rows = []
    for lo in LOWER_BOUNDS:
        gray = ~tier0 & (score >= lo) & (score < hi)
        flagged = tier0 | (~tier0 & (score >= hi)) | (gray & (asks | off))
        quarantined = tier0 | (~tier0 & (score >= hi)) | (gray & asks & off & ~established)
        rows.append({"lower bound": lo, "sent to Tier 2": gray.mean(), "recall": flagged[y].mean(),
                     "hard-positive recall": flagged[hard_pos].mean(), "legit flagged": int(flagged[~y].sum()),
                     "legit quarantined / spam": int(quarantined[~y].sum())})
    return pd.DataFrame(rows).set_index("lower bound")


def run(cfg: dict) -> dict:
    seed = cfg["seed"]
    seed_everything(seed)
    train_start, test_start = train.split_dates(cfg)
    val_start = test_start - timedelta(days=cfg["model"]["validation_days"])

    df, _, X_text, texts = train.build_feature_table(cfg, fit_end=val_start, save_snapshot=False)
    pre = (df["timestamp"] < val_start).to_numpy()
    fit = pre & (df["timestamp"] >= train_start).to_numpy()
    val = ((df["timestamp"] >= val_start) & (df["timestamp"] < test_start)).to_numpy()

    y_bin = df["label"].to_numpy()
    df["text_score"] = 0.0
    df.loc[pre, "text_score"] = oof_scores(X_text[pre], y_bin[pre], seed)
    df.loc[val, "text_score"] = make_lr(seed).fit(X_text[pre], y_bin[pre]).predict_proba(X_text[val])[:, 1]
    fill = {f: float(v) for f, v in df.loc[fit, FEATURES].median().items()}
    X_fit, X_val = model_input(df.loc[fit], fill), model_input(df.loc[val], fill)
    y = df["category"].map({c: i for i, c in enumerate(CATEGORIES)}).to_numpy()
    va = df.loc[val].reset_index(drop=True)

    sweep = []
    for params in GRID:
        p = BASE | params
        m = LGBMClassifier(objective="multiclass", **p, random_state=seed, verbose=-1).fit(X_fit, y[fit])
        score = 1 - m.predict_proba(X_val)[:, 0]
        sweep.append({**{k: p[k] for k in SHOWN}, "val PR-AUC": average_precision_score(va["label"], score),
                      "_params": p, "_model": m})
    sweep_df = pd.DataFrame(sweep)
    best = sweep_df.loc[sweep_df["val PR-AUC"].idxmax()]
    best_params = best["_params"]
    score = 1 - best["_model"].predict_proba(X_val)[:, 0]

    intent = IntentModel(seed).fit(X_text[pre], [t for t, k in zip(texts, pre) if k])
    intents = intent.predict(X_text[val], [t for t, k in zip(texts, val) if k])
    gz = gray_zone_sweep(cfg, va, score, intents)
    budget = cfg["cascade"]["banner_budget"] * int((va["label"] == 0).sum())
    ok = gz[gz["legit flagged"] <= budget]
    chosen_lo = float(ok.sort_values(["hard-positive recall", "legit flagged"], ascending=[False, True]).index[0]) \
        if len(ok) else LOWER_BOUNDS[0]

    cfg_params = cfg["model"]["lgbm"]
    params_match = all(np.isclose(float(cfg_params[k]), float(best_params[k])) for k in best_params)
    lo_match = np.isclose(cfg["cascade"]["gray_zone"][0], chosen_lo)
    md = f"""# Validation (model selection)

Validation window: {val_start:%Y-%m-%d} to {test_start:%Y-%m-%d} (last {cfg['model']['validation_days']} training days, {int(val.sum())} emails,
{int((va['label'] == 0).sum())} legit by observed label, {int(va['scenario'].str.startswith('hard_pos').sum())} hard positives). Everything was fitted on emails before
{val_start:%Y-%m-%d} only. Scores use the observed (noisy) labels. Generated by `make validate`.

## LightGBM settings (fixed: {", ".join(f"{k}={v}" for k, v in BASE.items())})

{table(sweep_df.drop(columns=["_model", "_params"]), {"val PR-AUC": ".4f", "reg_lambda": ".1f", "n_estimators": ".0f", "num_leaves": ".0f", "min_child_samples": ".0f"}, index=False)}

Chosen: {", ".join(f"{k}={best_params[k]}" for k in SHOWN)} (best validation PR-AUC).
**Config {"matches" if params_match else "DIFFERS"}.**

## Gray-zone lower bound (upper bound {cfg['cascade']['gray_zone'][1]})

Rule: the most hard positives caught while flagging at most {cfg['cascade']['banner_budget']:.0%} of legit mail
(≤{budget:.1f} emails here). "Flagged" = any action but DELIVER.

{table(gz, {"sent to Tier 2": ".1%", "recall": ".1%", "hard-positive recall": ".0%", "legit flagged": ".0f",
            "legit quarantined / spam": ".0f"})}

Chosen: **{chosen_lo}**. **Config {"matches" if lo_match else "DIFFERS"}.**
"""
    out = Path(cfg["paths"]["reports"])
    out.mkdir(parents=True, exist_ok=True)
    (out / "validation.md").write_text(md)
    print(md)
    if not (params_match and lo_match):
        raise SystemExit(f"Validation chose lgbm={best_params}, gray-zone lower bound={chosen_lo}; "
                         "update configs/default.yaml and rerun.")
    print("Config matches validation; refitting on the full training period.")
    train.run(cfg)
    return {"lgbm": best_params, "gray_zone_lo": chosen_lo, "sweep": sweep_df.drop(columns=["_model", "_params"]),
            "gray_zone": gz}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--config", default=None)
    run(load_config(ap.parse_args().config))


if __name__ == "__main__":
    main()
