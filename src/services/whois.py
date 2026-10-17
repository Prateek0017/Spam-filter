"""Mock WHOIS / RDAP domain-age lookup."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, timedelta

from src.common.domains import registrable_domain
from src.services.base import MockService, ServiceResult, stable_uniform


@dataclass(frozen=True)
class DomainInfo:
    domain: str
    created: date
    age_days: int         # relative to the email's timestamp (no look-ahead)


class WhoisService(MockService):
    name = "whois"

    def lookup(self, domain: str, as_of: datetime | date) -> ServiceResult[DomainInfo]:
        dom = registrable_domain(domain)
        as_of_d = as_of.date() if isinstance(as_of, datetime) else as_of

        def compute() -> tuple[DomainInfo, str]:
            created = self.intel.created_date(dom)
            source = "registry"
            if created is None:
                # Unknown domain: established (1–20 years), deterministic per domain.
                years = 1 + 19 * stable_uniform("whois", dom)
                created = date(2026, 1, 1) - timedelta(days=int(years * 365))
                source = "heuristic"
            age = max(0, (as_of_d - created).days)
            return DomainInfo(domain=dom, created=created, age_days=age), source

        return self._call(dom, compute)
