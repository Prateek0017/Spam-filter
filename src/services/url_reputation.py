"""Mock URL reputation (think Google Safe Browsing / PhishTank).

Real feeds lag behind fresh phishing infrastructure, so the generator deliberately
registers only a fraction of malicious domains here: a new phishing domain is often
"unknown", not "malicious". The ML tier has to cope with that.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from src.common.domains import URL_SHORTENERS, registrable_domain, url_host
from src.services.base import MockService, ServiceResult

Verdict = Literal["clean", "suspicious", "malicious", "unknown"]


@dataclass(frozen=True)
class UrlReputation:
    url: str
    domain: str
    verdict: Verdict
    is_shortener: bool


class UrlReputationService(MockService):
    name = "url_reputation"

    def lookup(self, url: str) -> ServiceResult[UrlReputation]:
        dom = registrable_domain(url_host(url))

        def compute() -> tuple[UrlReputation, str]:
            verdict: Verdict = self.intel.url_verdicts.get(dom, "unknown")  # type: ignore[assignment]
            source = "registry" if dom in self.intel.url_verdicts else "heuristic"
            return UrlReputation(url=url, domain=dom, verdict=verdict, is_shortener=dom in URL_SHORTENERS), source

        return self._call(dom, compute)
