"""Phase 2: the synthetic stream has the configured class mix and is reproducible."""
from __future__ import annotations

import os
import subprocess
import sys
from collections import Counter

import pytest

from src.common.config import REPO_ROOT, load_config
from src.data.generate import generate


@pytest.fixture(scope="module")
def generated():
    cfg = load_config()
    cfg["data"]["n_emails"] = 3000
    return cfg, *generate(cfg)


def test_class_mix_matches_config(generated) -> None:
    cfg, tenants, emails, _, n_noisy, _ = generated
    assert len(tenants) == cfg["data"]["n_tenants"] and len(emails) == 3000
    true = Counter(e.true_category for e in emails)
    for cat, frac in cfg["data"]["class_mix"].items():
        assert true[cat] / len(emails) == pytest.approx(frac, abs=0.005)
    # Noise touches only the observed label, at the configured rate.
    flipped = sum(e.category != e.true_category for e in emails)
    assert flipped == n_noisy == int(cfg["data"]["label_noise"] * len(emails))
    assert all(e.label == int(e.category != "legit") for e in emails)


def test_real_replies_are_in_sent_log_and_fake_ones_are_not(generated) -> None:
    """Legit threads leave a sent-mail record; attackers' 'RE:' subjects (and forged threads) do not."""
    _, _, emails, _, _, sent = generated
    log = {(m.from_addr, m.to_addr) for m in sent}
    threaded_legit = [e for e in emails if e.true_category == "legit" and e.thread]
    assert threaded_legit and all(e.subject.lower().startswith("re:") for e in threaded_legit)
    assert all((e.to_addr, e.from_addr) in log for e in threaded_legit)
    fake = [e for e in emails if e.scenario.startswith(("bec:", "phishing:"))
            and e.subject.lower().startswith(("re:", "fw"))]
    assert len(fake) > 20 and not any((e.to_addr, e.from_addr) in log for e in fake)


def test_stream_is_time_ordered_and_has_hard_cases(generated) -> None:
    _, _, emails, _, _, _ = generated
    assert all(a.timestamp <= b.timestamp for a, b in zip(emails, emails[1:]))
    scenarios = {e.scenario.split(":")[0] for e in emails}
    assert {"hard_neg", "hard_pos"} <= scenarios


_DIGEST = (
    "import hashlib; from src.common.config import load_config; from src.data.generate import generate;"
    "cfg = load_config(); cfg['data']['n_emails'] = 1500; _, emails, intel, _, sent = generate(cfg);"
    "h = hashlib.sha256(); [h.update(x.model_dump_json().encode()) for x in emails + sent];"
    "h.update(repr(sorted(intel.domain_created.items())).encode()); print(h.hexdigest())"
)


def test_same_output_across_processes() -> None:
    """Same seed -> byte-identical data, even with different Python hash seeds (set ordering)."""
    def digest(hash_seed: str) -> str:
        env = {**os.environ, "PYTHONHASHSEED": hash_seed}
        return subprocess.run([sys.executable, "-c", _DIGEST], cwd=REPO_ROOT, env=env,
                              capture_output=True, text=True, check=True).stdout.strip()

    assert digest("1") == digest("2")
