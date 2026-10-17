"""Phase 1: mocked services are deterministic, respect timeouts and serve registry intel."""
from __future__ import annotations

import time
from datetime import date, datetime

import pytest

from src.common.config import load_config
from src.common.domains import address_domain, is_freemail, registrable_domain
from src.data.schema import Attachment
from src.services import ThreatIntel, build_services
from src.services.base import LatencyModel


@pytest.fixture()
def intel() -> ThreatIntel:
    return ThreatIntel(
        domain_created={"paypa1.com": "2026-05-01"},
        ip_reputation={"203.0.113.9": 0.05},
        ip_country={"203.0.113.9": "RU"},
        url_verdicts={"evil-login.com": "malicious", "acme.com": "clean"},
        malware_hashes={"deadbeef"},
    )


@pytest.fixture()
def services(intel: ThreatIntel):
    return build_services(load_config(), intel=intel, simulate_latency=False)


def test_domain_helpers() -> None:
    assert address_domain("Jane Doe <jane@Mail.Acme.co.uk>") == "mail.acme.co.uk"
    assert registrable_domain("mail.acme.co.uk") == "acme.co.uk"
    assert is_freemail("gmail.com") and not is_freemail("acme.com")


def test_ip_reputation_registry_and_determinism(services) -> None:
    bad = services.ip.lookup("203.0.113.9").value
    assert bad is not None and bad.listed and bad.country == "RU" and bad.geo_risk > 0.5
    a, b = services.ip.lookup("198.51.100.7"), services.ip.lookup("198.51.100.7")
    assert a.value == b.value and a.latency_ms == b.latency_ms and a.source == "heuristic"


def test_whois_age_is_relative_to_email_time(services) -> None:
    r1 = services.whois.lookup("login.paypa1.com", as_of=date(2026, 5, 11)).value
    r2 = services.whois.lookup("paypa1.com", as_of=datetime(2026, 6, 1, 9, 0)).value
    assert r1 is not None and r1.domain == "paypa1.com" and r1.age_days == 10
    assert r2 is not None and r2.age_days == 31


def test_url_reputation(services) -> None:
    assert services.url.lookup("https://secure.evil-login.com/x").value.verdict == "malicious"
    assert services.url.lookup("https://never-seen.example").value.verdict == "unknown"
    assert services.url.lookup("bit.ly/abc").value.is_shortener


def test_virus_scan_registry_hash_and_clean_file(services) -> None:
    assert services.virus.scan(Attachment(filename="inv.pdf", sha256="deadbeef")).value.infected
    clean = services.virus.scan(Attachment(filename="notes.pdf", sha256="cafe")).value
    assert clean is not None and not clean.infected


def test_virus_scan_async_submit(services) -> None:
    fut = services.virus.submit(Attachment(filename="inv.pdf", sha256="deadbeef"))
    assert fut.result(timeout=5).value.infected


def test_timeout_returns_none(intel: ThreatIntel) -> None:
    from src.services.ip_reputation import IPReputationService

    slow = IPReputationService(intel, LatencyModel(p50_ms=500, sigma=0.0, timeout_ms=50))
    r = slow.lookup("1.2.3.4")
    assert r.timed_out and r.value is None and r.latency_ms == 50


def test_latency_distribution_and_real_sleep(intel: ThreatIntel) -> None:
    from src.services.ip_reputation import IPReputationService

    lm = LatencyModel(p50_ms=4, sigma=0.5, timeout_ms=50)
    samples = sorted(lm.sample(f"k{i}") for i in range(2000))
    assert 3.0 < samples[1000] < 5.0                      # median ~ p50
    svc = IPReputationService(intel, LatencyModel(p50_ms=20, sigma=0.0, timeout_ms=100), simulate_latency=True)
    t0 = time.perf_counter()
    svc.lookup("1.2.3.4")
    assert (time.perf_counter() - t0) * 1000 >= 19
