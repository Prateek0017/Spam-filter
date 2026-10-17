"""Tier 2 intent check: what is this email asking the reader to do?

A TF-IDF one-vs-rest logistic regression predicts four request intents. There are no
hand-labelled intents, so training labels come from simple patterns (weak supervision);
the classifier generalises them across phrasings and gives a probability instead of a hit.
"""
from __future__ import annotations

import re

import numpy as np
from scipy.sparse import csr_matrix
from sklearn.linear_model import LogisticRegression
from sklearn.multiclass import OneVsRestClassifier

INTENT_PATTERNS: dict[str, re.Pattern[str]] = {
    "payment": re.compile(r"\b(wire|payment|remit|bank (details|account)|beneficiary|direct deposit|routing|"
                          r"process (the |a )?(invoice|payment|wire))\b"),
    "gift_card": re.compile(r"\b(gift cards?|apple cards?|itunes|the codes)\b"),
    "credential": re.compile(r"\b(password|sign in|log ?in|verify your (account|login)|credentials)\b"),
    "urgency": re.compile(r"\b(urgent(ly)?|asap|today|immediately|end of day|overdue|expires?)\b"),
}
INTENTS = list(INTENT_PATTERNS)
RISKY_INTENTS = ("payment", "gift_card", "credential")


def weak_labels(texts: list[str]) -> np.ndarray:
    return np.array([[int(bool(p.search(t.lower()))) for p in INTENT_PATTERNS.values()] for t in texts])


class IntentModel:
    def __init__(self, seed: int = 42) -> None:
        self.clf = OneVsRestClassifier(LogisticRegression(C=2.0, max_iter=2000, random_state=seed))

    def fit(self, X: csr_matrix, texts: list[str]) -> "IntentModel":
        self.clf.fit(X, weak_labels(texts))
        return self

    def predict(self, X: csr_matrix) -> list[dict[str, float]]:
        P = self.clf.predict_proba(X)
        return [dict(zip(INTENTS, map(float, row))) for row in P]
