"""Mock attachment virus-scan API.

This is the slow, *asynchronous* service: median ~2.5s with a heavy tail, so it often
finishes after the 5s provider deadline. The cascade never waits on it; if it later
reports an infection, the pipeline performs post-delivery remediation (pulls the mail).
"""
from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass

from src.data.schema import Attachment
from src.services.base import MockService, ServiceResult, stable_uniform

RISKY_EXTENSIONS = frozenset({"exe", "js", "vbs", "scr", "iso", "img", "lnk", "hta", "bat", "cmd", "jar"})
MACRO_EXTENSIONS = frozenset({"docm", "xlsm", "pptm", "xls", "doc"})


@dataclass(frozen=True)
class ScanVerdict:
    sha256: str
    infected: bool
    signature: str | None


class VirusScanService(MockService):
    name = "virus_scan"

    def __init__(self, *args, max_workers: int = 8, **kwargs) -> None:  # type: ignore[no-untyped-def]
        super().__init__(*args, **kwargs)
        self._pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="virus-scan")

    def scan(self, att: Attachment) -> ServiceResult[ScanVerdict]:
        """Blocking scan (runs in the async worker pool in production)."""
        key = att.sha256 or att.filename

        def compute() -> tuple[ScanVerdict, str]:
            if att.sha256 in self.intel.malware_hashes:
                return ScanVerdict(att.sha256, True, "Mock.Trojan.Generic"), "registry"
            ext = att.filename.rsplit(".", 1)[-1].lower() if "." in att.filename else ""
            # Unknown file: sandbox detonation catches most macro droppers / executables.
            if (att.has_macro or ext in RISKY_EXTENSIONS) and stable_uniform("av", key) < 0.85:
                return ScanVerdict(att.sha256, True, "Mock.Heur.Dropper"), "heuristic"
            return ScanVerdict(att.sha256, False, None), "heuristic"

        return self._call(key, compute)

    def submit(self, att: Attachment) -> "Future[ServiceResult[ScanVerdict]]":
        """Fire-and-forget scan; the caller attaches a remediation callback."""
        return self._pool.submit(self.scan, att)
