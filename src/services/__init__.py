"""Mocked external services with deterministic answers and configurable latency."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.services.base import LatencyModel, ServiceResult, ThreatIntel
from src.services.ip_reputation import IPReputationService
from src.services.url_reputation import UrlReputationService
from src.services.virus_scan import VirusScanService
from src.services.whois import WhoisService


@dataclass
class Services:
    ip: IPReputationService
    whois: WhoisService
    url: UrlReputationService
    virus: VirusScanService
    intel: ThreatIntel


def build_services(cfg: dict[str, Any], intel: ThreatIntel | None = None,
                   simulate_latency: bool = False, simulate_scan_latency: bool | None = None) -> Services:
    """Construct all mocks from the `services:` config block and the intel snapshot.

    simulate_scan_latency defaults to simulate_latency; batch evaluation keeps the slow async scan
    virtual while the sync lookups really sleep."""
    if intel is None:
        intel = ThreatIntel.load(Path(cfg["paths"]["raw"]) / "intel.json")
    sc = cfg["services"]
    mk = lambda name: LatencyModel.from_config(sc[name])  # noqa: E731
    return Services(
        ip=IPReputationService(intel, mk("ip_reputation"), simulate_latency),
        whois=WhoisService(intel, mk("whois"), simulate_latency),
        url=UrlReputationService(intel, mk("url_reputation"), simulate_latency),
        virus=VirusScanService(intel, mk("virus_scan"),
                               simulate_latency if simulate_scan_latency is None else simulate_scan_latency),
        intel=intel,
    )


__all__ = ["Services", "build_services", "ThreatIntel", "LatencyModel", "ServiceResult"]
