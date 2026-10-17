"""Shared machinery for the mocked external services.

Each mock is *deterministic*: answers come from a threat-intel registry written by the
data generator (data/processed/intel.json) or, for keys it has never seen, from a stable
hash of the key. Latency is drawn from a lognormal distribution whose RNG is seeded from
the key, so the same lookup always costs the same simulated time.

Latency can be *simulated* (real `time.sleep`, used by the API/demo) or *virtual*
(reported but not slept, used for batch evaluation so 25k emails don't take hours).
"""
from __future__ import annotations

import hashlib
import json
import math
import time
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any, Callable, Generic, TypeVar

import numpy as np

T = TypeVar("T")


def stable_hash(*parts: str) -> int:
    """Process-independent 64-bit hash (Python's hash() is salted per process)."""
    h = hashlib.blake2b("|".join(parts).encode(), digest_size=8)
    return int.from_bytes(h.digest(), "big")


def stable_uniform(*parts: str) -> float:
    """Deterministic pseudo-random float in [0, 1) derived from the key."""
    return stable_hash(*parts) / 2**64


@dataclass(frozen=True)
class LatencyModel:
    p50_ms: float
    sigma: float = 0.5
    timeout_ms: float = 1000.0

    def sample(self, key: str) -> float:
        """Lognormal latency with median p50_ms, seeded from the lookup key."""
        rng = np.random.default_rng(stable_hash("latency", key))
        return float(self.p50_ms * math.exp(self.sigma * rng.standard_normal()))

    @classmethod
    def from_config(cls, cfg: dict[str, Any]) -> "LatencyModel":
        return cls(p50_ms=cfg["p50_ms"], sigma=cfg.get("sigma", 0.5), timeout_ms=cfg.get("timeout_ms", 1000))


@dataclass
class ServiceResult(Generic[T]):
    """Envelope for every service call. `value` is None when the call timed out."""
    value: T | None
    latency_ms: float
    timed_out: bool = False
    source: str = "registry"          # "registry" | "heuristic" | "timeout"


@dataclass
class ThreatIntel:
    """In-memory snapshot of the intel the mocks serve. Populated by the data generator."""
    domain_created: dict[str, str] = field(default_factory=dict)    # registrable domain -> ISO date
    ip_reputation: dict[str, float] = field(default_factory=dict)   # ip -> score in [0,1], 1 = good
    ip_country: dict[str, str] = field(default_factory=dict)        # ip -> ISO country code
    url_verdicts: dict[str, str] = field(default_factory=dict)      # registrable domain -> verdict
    malware_hashes: set[str] = field(default_factory=set)

    @classmethod
    def load(cls, path: str | Path) -> "ThreatIntel":
        p = Path(path)
        if not p.exists():
            return cls()
        raw = json.loads(p.read_text())
        raw["malware_hashes"] = set(raw.get("malware_hashes", []))
        return cls(**raw)

    def save(self, path: str | Path) -> None:
        d = self.__dict__.copy()
        d["malware_hashes"] = sorted(self.malware_hashes)
        Path(path).write_text(json.dumps(d))

    def created_date(self, domain: str) -> date | None:
        iso = self.domain_created.get(domain)
        return date.fromisoformat(iso) if iso else None


class MockService:
    """Base class: applies the latency model and the client-side timeout."""

    name: str = "service"

    def __init__(self, intel: ThreatIntel, latency: LatencyModel, simulate_latency: bool = False) -> None:
        self.intel = intel
        self.latency = latency
        self.simulate_latency = simulate_latency

    def _call(self, key: str, compute: Callable[[], tuple[T, str]]) -> ServiceResult[T]:
        latency = self.latency.sample(f"{self.name}:{key}")
        if latency > self.latency.timeout_ms:
            # Client gives up at the timeout; caller must treat the signal as unknown.
            if self.simulate_latency:
                time.sleep(self.latency.timeout_ms / 1000)
            return ServiceResult(value=None, latency_ms=self.latency.timeout_ms, timed_out=True, source="timeout")
        if self.simulate_latency:
            time.sleep(latency / 1000)
        value, source = compute()
        return ServiceResult(value=value, latency_ms=latency, source=source)
