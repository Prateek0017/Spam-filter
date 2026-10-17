"""Core data model shared by the generator, feature extraction, cascade and API.

Pydantic models validate pasted demo input and serialise generated data to JSONL.
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


class SentMessage(BaseModel):
    """An email a tenant mailbox sent (the sent-mail log). Feeds relationship history only."""
    tenant_id: str
    from_addr: str                     # the tenant mailbox
    to_addr: str                       # the external or internal correspondent
    timestamp: datetime
    subject: str = ""


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

    # Labels (generator only; never used as features)
    category: str | None = None        # observed label, one of CATEGORIES (includes ~2% label noise)
    true_category: str | None = None   # ground truth before noise
    label: int | None = None           # 1 if `category` is malicious (anything but legit)
    scenario: str | None = None        # e.g. "legit:vendor_invoice", "hard_pos:compromised_vendor"


class Tenant(BaseModel):
    tenant_id: str
    name: str
    domain: str
    industry: Industry
    mailboxes: list[str]
    names: dict[str, str]              # mailbox address -> display name
    executives: dict[str, str]         # role -> mailbox address (CEO, CFO, ...)
    vendors: list[str]                 # registrable domains of real suppliers / partners


class Action(str, Enum):
    DELIVER = "DELIVER"
    WARNING_BANNER = "WARNING_BANNER"
    SPAM_FOLDER = "SPAM_FOLDER"
    QUARANTINE = "QUARANTINE"
