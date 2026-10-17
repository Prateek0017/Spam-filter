"""Domain / address parsing helpers shared by rules, features and services."""
from __future__ import annotations

from functools import lru_cache
from urllib.parse import urlparse

import tldextract

# Offline extractor: uses the bundled public-suffix snapshot, never fetches from the network.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())

FREEMAIL_DOMAINS: frozenset[str] = frozenset(
    {
        "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "icloud.com",
        "proton.me", "protonmail.com", "gmx.com", "mail.com", "yandex.com", "zoho.com",
    }
)

# Brands attackers most often impersonate; the lookalike rule protects these plus each tenant's
# own domain and its known vendors.
BRAND_DOMAINS: frozenset[str] = frozenset({"microsoft.com", "docusign.net", "paypal.com", "dhl.com", "zoom.us"})

URL_SHORTENERS: frozenset[str] = frozenset(
    {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly"}
)


def address_domain(addr: str) -> str:
    """'Jane <jane@Mail.Acme.com>' or 'jane@mail.acme.com' -> 'mail.acme.com'."""
    addr = addr.strip().strip("<>").lower()
    if "<" in addr:
        addr = addr.split("<", 1)[1].rstrip(">")
    return addr.rsplit("@", 1)[-1]


@lru_cache(maxsize=65536)
def registrable_domain(host: str) -> str:
    """'mail.acme.co.uk' -> 'acme.co.uk'. Falls back to the input for unknown suffixes."""
    ext = _EXTRACT(host.lower())
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return host.lower()


def url_host(url: str) -> str:
    """Hostname of a URL (tolerates missing scheme)."""
    if "://" not in url:
        url = "http://" + url
    return (urlparse(url).hostname or "").lower()


def is_freemail(domain: str) -> bool:
    return registrable_domain(domain) in FREEMAIL_DOMAINS
