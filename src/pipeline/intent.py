"""Tier 2 intent check: what is this email asking the reader to do?

A TF-IDF one-vs-rest logistic regression predicts four request intents. There are no
hand-labelled intents, so training labels come from simple patterns (weak supervision);
the classifier generalises them across phrasings and gives a probability instead of a hit.

Next to it, a deterministic keyword layer catches what a bag-of-words model trained on this
data can miss: any money request (a currency amount, or words like pay / fee / deposit /
transfer) and any request to move off email (a phone number, WhatsApp, Telegram). If it fires,
the intent counts as present whatever the classifier says.
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
MONEY_AMOUNT = re.compile(
    r"(?:[$€£₹]|\b(?:usd|eur|gbp|inr|rs\.?)\s?)\s?\d[\d,.]*"
    r"|\b\d[\d,.]*\s?(?:dollars?|usd|eur|euros?|pounds?|gbp|rupees?|rs|inr|bitcoin|btc)\b", re.I)
MONEY_WORDS = re.compile(r"\b(pay|paid|payment|fees?|deposit|transfer|wire|remit|bitcoin|btc|crypto|gift cards?)\b",
                         re.I)
CHAT_APPS = re.compile(r"\b(whats ?app|telegram|signal app|viber|wechat)\b|t\.me/", re.I)
PHONE_LIKE = re.compile(r"(?<![\w$€£₹.,])\+?\(?\d[\d\s().-]{7,}\d(?![\w.,])")

INTENTS = [*INTENT_PATTERNS, "off_channel"]
RISKY_INTENTS = ("payment", "gift_card", "credential", "off_channel")


def asks_for_money(text: str) -> bool:
    return bool(MONEY_AMOUNT.search(text) or MONEY_WORDS.search(text))


def asks_off_channel(text: str) -> bool:
    """A chat app, or a phone number (9-15 digits, so invoice / order numbers don't count)."""
    if CHAT_APPS.search(text):
        return True
    return any(9 <= sum(c.isdigit() for c in m.group()) <= 15 for m in PHONE_LIKE.finditer(text))


def weak_labels(texts: list[str]) -> np.ndarray:
    return np.array([[int(bool(p.search(t.lower()))) for p in INTENT_PATTERNS.values()] for t in texts])


class IntentModel:
    def __init__(self, seed: int = 42) -> None:
        self.clf = OneVsRestClassifier(LogisticRegression(C=2.0, max_iter=2000, random_state=seed))

    def fit(self, X: csr_matrix, texts: list[str]) -> "IntentModel":
        self.clf.fit(X, weak_labels(texts))
        return self

    def predict(self, X: csr_matrix, texts: list[str]) -> list[dict[str, float]]:
        """Classifier probabilities, raised to 1.0 where the keyword layer fires."""
        out = []
        for row, text in zip(self.clf.predict_proba(X), texts):
            intents = dict(zip(INTENT_PATTERNS, map(float, row)))
            if asks_for_money(text):
                intents["payment"] = 1.0
            intents["off_channel"] = 1.0 if asks_off_channel(text) else 0.0
            out.append(intents)
        return out
