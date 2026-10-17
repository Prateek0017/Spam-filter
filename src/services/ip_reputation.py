"""Mock IP reputation + geolocation (think Spamhaus / MaxMind)."""
from __future__ import annotations

from dataclasses import dataclass

from src.services.base import MockService, ServiceResult, stable_uniform

# Coarse geo risk prior for the *mock*; in production this is learned per tenant from
# where its legitimate correspondents actually send from.
COUNTRY_RISK: dict[str, float] = {
    "US": 0.1, "GB": 0.1, "DE": 0.1, "FR": 0.1, "NL": 0.15, "IN": 0.25, "JP": 0.1, "CA": 0.1,
    "SG": 0.15, "IE": 0.1, "BR": 0.35, "CN": 0.4, "RU": 0.6, "NG": 0.7, "VN": 0.5, "UA": 0.45,
    "RO": 0.45, "KP": 0.9, "ZZ": 0.5,  # ZZ = unknown
}
_UNKNOWN_COUNTRIES = ["US", "DE", "GB", "IN", "BR", "CN", "RU", "VN", "NG", "RO"]


@dataclass(frozen=True)
class IPReputation:
    score: float          # 0 = known bad, 1 = clean
    country: str
    geo_risk: float
    listed: bool          # on a blocklist (score < 0.2)


class IPReputationService(MockService):
    name = "ip_reputation"

    def lookup(self, ip: str) -> ServiceResult[IPReputation]:
        def compute() -> tuple[IPReputation, str]:
            if ip in self.intel.ip_reputation:
                score = self.intel.ip_reputation[ip]
                country = self.intel.ip_country.get(ip, "ZZ")
                source = "registry"
            else:
                # Unseen IP: mostly neutral-to-good, deterministic per IP.
                score = round(0.45 + 0.5 * stable_uniform("ipscore", ip), 3)
                country = _UNKNOWN_COUNTRIES[int(stable_uniform("ipgeo", ip) * len(_UNKNOWN_COUNTRIES))]
                source = "heuristic"
            rep = IPReputation(score=score, country=country,
                               geo_risk=COUNTRY_RISK.get(country, 0.5), listed=score < 0.2)
            return rep, source

        return self._call(ip, compute)
