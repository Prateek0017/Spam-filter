"""TF-IDF + logistic regression text score (P(malicious) from subject + body)."""
from __future__ import annotations

import numpy as np
from scipy.sparse import csr_matrix
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold


def make_vectorizer() -> TfidfVectorizer:
    return TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_features=30000, sublinear_tf=True)


def make_lr(seed: int) -> LogisticRegression:
    return LogisticRegression(C=2.0, max_iter=2000, class_weight="balanced", random_state=seed)


def oof_scores(X: csr_matrix, y: np.ndarray, seed: int, folds: int = 5) -> np.ndarray:
    """Out-of-fold P(malicious) so the downstream model never sees a score fit on its own row."""
    out = np.zeros(X.shape[0])
    for tr, va in StratifiedKFold(folds, shuffle=True, random_state=seed).split(X, y):
        out[va] = make_lr(seed).fit(X[tr], y[tr]).predict_proba(X[va])[:, 1]
    return out
