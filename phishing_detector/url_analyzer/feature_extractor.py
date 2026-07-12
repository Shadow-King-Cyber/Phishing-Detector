"""URL feature extraction for phishing detection."""

import re
import ipaddress
from urllib.parse import urlparse
from dataclasses import dataclass, field

KNOWN_DOMAINS = [
    "google.com", "facebook.com", "twitter.com", "x.com", "instagram.com",
    "linkedin.com", "microsoft.com", "apple.com", "amazon.com", "netflix.com",
    "paypal.com", "ebay.com", "github.com", "youtube.com", "whatsapp.com",
    "telegram.org", "zoom.us", "dropbox.com", "adobe.com", "salesforce.com",
    "office.com", "live.com", "outlook.com", "yahoo.com", "twitch.tv",
    "reddit.com", "tiktok.com", "spotify.com", "cloudflare.com",
]


def _levenshtein(a: str, b: str) -> int:
    if len(a) < len(b):
        return _levenshtein(b, a)
    if not b:
        return len(a)
    prev = range(len(b) + 1)
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(
                prev[j + 1] if ca == cb
                else 1 + min((prev[j], curr[j], prev[j + 1]))
            )
        prev = curr
    return prev[-1]


@dataclass
class URLFeatures:
    url: str
    length: int = 0
    domain: str = ""
    has_ip_address: bool = False
    num_special_chars: int = 0
    num_subdomains: int = 0
    has_https: bool = False
    num_hyphens: int = 0
    num_digits: int = 0
    num_at_symbols: int = 0
    has_suspicious_tld: bool = False
    typosquatting_matches: list = field(default_factory=list)
    has_shortening_service: bool = False
    path_depth: int = 0
    has_double_slash_redirect: bool = False

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "length": self.length,
            "domain": self.domain,
            "has_ip_address": self.has_ip_address,
            "num_special_chars": self.num_special_chars,
            "num_subdomains": self.num_subdomains,
            "has_https": self.has_https,
            "num_hyphens": self.num_hyphens,
            "num_digits": self.num_digits,
            "num_at_symbols": self.num_at_symbols,
            "has_suspicious_tld": self.has_suspicious_tld,
            "typosquatting_matches": self.typosquatting_matches,
            "has_shortening_service": self.has_shortening_service,
            "path_depth": self.path_depth,
            "has_double_slash_redirect": self.has_double_slash_redirect,
        }


SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".work", ".buzz", ".tk", ".ml", ".ga", ".cf",
    ".gq", ".pw", ".cc", ".icu", ".fun", ".site", ".online", ".info",
}

SHORTENING_SERVICES = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "v.gd",
    "ow.ly", "rb.gy", "cutt.ly", "shorturl.at", "lnkd.in",
}


class URLFeatureExtractor:
    """Extracts suspicious features from a URL."""

    def extract(self, url: str) -> URLFeatures:
        features = URLFeatures(url=url)
        parsed = urlparse(url if "://" in url else f"http://{url}")

        domain = parsed.hostname or ""
        features.domain = domain
        features.length = len(url)
        features.has_https = parsed.scheme == "https"

        features.has_ip_address = self._check_ip(domain)
        features.num_subdomains = max(0, domain.count(".") - 1)
        features.num_hyphens = domain.count("-")
        features.num_digits = sum(c.isdigit() for c in domain)
        features.num_at_symbols = url.count("@")
        features.num_special_chars = len(re.findall(r"[^a-zA-Z0-9./:?=&#%-]", url))
        features.has_suspicious_tld = self._check_suspicious_tld(domain)
        features.typosquatting_matches = self._check_typosquatting(domain)
        features.has_shortening_service = domain.lower() in SHORTENING_SERVICES
        features.path_depth = len([p for p in parsed.path.split("/") if p])
        features.has_double_slash_redirect = "//" in parsed.path

        return features

    def _check_ip(self, domain: str) -> bool:
        try:
            ipaddress.ip_address(domain)
            return True
        except ValueError:
            return False

    def _check_suspicious_tld(self, domain: str) -> bool:
        for tld in SUSPICIOUS_TLDS:
            if domain.lower().endswith(tld):
                return True
        return False

    def _check_typosquatting(self, domain: str, max_distance: int = 2) -> list:
        matches = []
        base_domain = domain.split(":")[0].lower()

        for known in KNOWN_DOMAINS:
            known_base = known.split(".")[0]
            domain_base = base_domain.split(".")[0]

            if not domain_base or not known_base:
                continue
            if domain_base == known_base:
                continue

            dist = _levenshtein(domain_base, known_base)
            if 0 < dist <= max_distance:
                matches.append({"target": known, "distance": dist})

        return matches
