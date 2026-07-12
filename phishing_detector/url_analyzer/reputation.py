"""Reputation checking via public APIs (VirusTotal, PhishTank)."""

import os
import logging
from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests

logger = logging.getLogger(__name__)


@dataclass
class ReputationResult:
    source: str = ""
    is_known_phishing: bool = False
    positives: int = 0
    total_engines: int = 0
    detail: str = ""
    error: str = ""
    raw_response: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "is_known_phishing": self.is_known_phishing,
            "positives": self.positives,
            "total_engines": self.total_engines,
            "detail": self.detail,
            "error": self.error,
        }


class ReputationChecker:
    """Check URL reputation via VirusTotal and PhishTank APIs."""

    VT_BASE = "https://www.virustotal.com/api/v3"
    PHISHTANK_BASE = "http://data.phishtank.com/data"

    def __init__(
        self,
        vt_api_key: str | None = None,
        phishtank_api_key: str | None = None,
    ):
        self.vt_api_key = vt_api_key or os.environ.get("VT_API_KEY", "")
        self.phishtank_api_key = phishtank_api_key or os.environ.get(
            "PHISHTANK_API_KEY", ""
        )

    def check(self, url: str) -> list[ReputationResult]:
        results = []
        if self.vt_api_key:
            results.append(self._check_virustotal(url))
        if self.phishtank_api_key:
            results.append(self._check_phishtank(url))

        if not results:
            r = ReputationResult(source="none")
            r.error = "No API keys configured. Set VT_API_KEY or PHISHTANK_API_KEY."
            results.append(r)

        return results

    def _check_virustotal(self, url: str) -> ReputationResult:
        result = ReputationResult(source="virustotal")
        try:
            import base64

            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            resp = requests.get(
                f"{self.VT_BASE}/urls/{url_id}",
                headers={"x-apikey": self.vt_api_key},
                timeout=15,
            )

            if resp.status_code == 200:
                data = resp.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                result.positives = stats.get("malicious", 0) + stats.get(
                    "suspicious", 0
                )
                result.total_engines = sum(stats.values())
                result.is_known_phishing = result.positives > 0
                result.raw_response = stats
            elif resp.status_code == 404:
                result.detail = "URL not found in VirusTotal database."
            else:
                result.error = f"VT API returned status {resp.status_code}"
        except requests.RequestException as e:
            result.error = f"VT request failed: {e}"

        return result

    def _check_phishtank(self, url: str) -> ReputationResult:
        result = ReputationResult(source="phishtank")
        try:
            params = {"url": url, "format": "json"}
            headers = {"User-Agent": "phishing-detector-tool"}
            if self.phishtank_api_key:
                params["key"] = self.phishtank_api_key

            resp = requests.get(
                f"{self.PHISHTANK_BASE}/online-valid.json",
                params=params,
                headers=headers,
                timeout=15,
            )

            if resp.status_code == 200:
                entries = resp.json()
                if isinstance(entries, list) and len(entries) > 0:
                    result.is_known_phishing = True
                    result.positives = len(entries)
                    result.detail = f"Found in PhishTank database ({len(entries)} entries)."
                    result.raw_response = entries[0] if entries else {}
            elif resp.status_code == 404:
                result.detail = "URL not found in PhishTank database."
            else:
                result.error = f"PhishTank API returned status {resp.status_code}"
        except requests.RequestException as e:
            result.error = f"PhishTank request failed: {e}"

        return result
