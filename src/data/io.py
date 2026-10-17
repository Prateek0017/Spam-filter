"""Load generated data from disk."""
from __future__ import annotations

import json
from pathlib import Path

from src.data.schema import Email, SentMessage, Tenant


def load_tenants(path: str | Path) -> list[Tenant]:
    return [Tenant.model_validate(t) for t in json.loads(Path(path).read_text())]


def load_emails(path: str | Path) -> list[Email]:
    with open(path) as f:
        return [Email.model_validate_json(line) for line in f]


def load_sent(path: str | Path) -> list[SentMessage]:
    """Sent-mail log; empty if the file is missing."""
    if not Path(path).exists():
        return []
    with open(path) as f:
        return [SentMessage.model_validate_json(line) for line in f]
