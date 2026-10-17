"""Configuration loading and global seeding."""
from __future__ import annotations

import os
import random
from pathlib import Path
from typing import Any

import numpy as np
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG = REPO_ROOT / "configs" / "default.yaml"


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    """Load the YAML config; relative paths inside `paths:` are resolved against the repo root."""
    cfg_path = Path(path) if path else DEFAULT_CONFIG
    with open(cfg_path) as f:
        cfg: dict[str, Any] = yaml.safe_load(f)
    cfg["paths"] = {k: str(REPO_ROOT / v) for k, v in cfg.get("paths", {}).items()}
    return cfg


def seed_everything(seed: int) -> np.random.Generator:
    """Seed Python and NumPy global RNGs and return a fresh Generator for explicit use."""
    random.seed(seed)
    np.random.seed(seed)
    os.environ["PYTHONHASHSEED"] = str(seed)
    return np.random.default_rng(seed)
