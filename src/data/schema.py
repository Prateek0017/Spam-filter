"""Core data model shared by the generator, feature extraction, cascade and API.

Pydantic models are used so the same schema validates API input (FastAPI) and
serialises generated data to JSONL.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field

AuthResult = Literal["pass", "fail", "softfail", "none"]

# Attack categories. "legit" is the negative class; everything else is malicious (label=1).
CATEGORIES: tuple[str, ...] = ("legit", "spam", "phishing", "bec", "malware")


class Industry(str, Enum):
    MANUFACTURING = "manufacturing"
    PHARMA = "pharma"
    FINTECH = "fintech"
    RETAIL = "retail"
    LEGAL = "legal"
    LOGISTICS = "logistics"
    HEALTHCARE = "healthcare"
    CONSTRUCTION = "construction"
    SAAS = "saas"
    EDUCATION = "education"


class AuthResults(BaseModel):
    spf: AuthResult = "pass"
    dkim: AuthResult = "pass"
    dmarc: AuthResult = "pass"


class Url(BaseModel):
    href: str
    anchor_text: str = ""


class Attachment(BaseModel):
    filename: str
    content_type: str = "application/octet-stream"
    size_bytes: int = 0
    sha256: str = ""
    has_macro: bool = False


class ThreadMessage(BaseModel):
    """A prior message in the same thread (most recent last)."""
    from_addr: str
    timestamp: datetime
    subject: str = ""
    body: str = ""


class Email(BaseModel):
    message_id: str
    tenant_id: str
    to_addr: str                       # recipient mailbox inside the tenant
    timestamp: datetime
    from_addr: str
    from_display: str = ""
    reply_to: str | None = None
    subject: str = ""
    body: str = ""
    auth: AuthResults = Field(default_factory=AuthResults)
    sender_ip: str = "0.0.0.0"
    urls: list[Url] = Field(default_factory=list)
    attachments: list[Attachment] = Field(default_factory=list)
    thread_id: str | None = None
    thread: list[ThreadMessage] = Field(default_factory=list)
    headers: dict[str, str] = Field(default_factory=dict)

    # Ground truth (generator only; never used as a feature)
    label: int | None = None           # 1 = malicious, 0 = legit (may contain injected noise)
    category: str | None = None        # one of CATEGORIES (true category, before noise)
    scenario: str | None = None        # e.g. "hard_neg:cfo_urgent_payment", "hard_pos:compromised_vendor"


class Tenant(BaseModel):
    tenant_id: str
    name: str
    domain: str
    industry: Industry
    mailboxes: list[str]
    executives: dict[str, str]         # role -> mailbox address (CEO, CFO, ...)
    vendors: list[str]                 # registrable domains of real suppliers / partners


class Action(str, Enum):
    DELIVER = "DELIVER"
    DELIVER_WITH_WARNING_BANNER = "DELIVER_WITH_WARNING_BANNER"
    SPAM_FOLDER = "SPAM_FOLDER"
    QUARANTINE = "QUARANTINE"
