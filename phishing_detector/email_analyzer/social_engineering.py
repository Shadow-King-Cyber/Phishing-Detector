"""Social engineering detection via keyword/pattern rules."""

import re
from dataclasses import dataclass, field


@dataclass
class SEResult:
    category: str
    matched_keywords: list = field(default_factory=list)
    matched_patterns: list = field(default_factory=list)
    severity: str = "low"

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "matched_keywords": self.matched_keywords,
            "matched_patterns": self.matched_patterns,
            "severity": self.severity,
        }


KEYWORD_RULES: dict[str, dict] = {
    "urgency": {
        "keywords": [
            "act now", "urgent", "immediately", "expires today",
            "limited time", "last chance", "hurry", "deadline",
            "within 24 hours", "right away", "don't delay",
            "final warning", "time sensitive", "before it's too late",
            "expires in", "only left", "ending soon", "don't miss out",
        ],
        "severity": "medium",
    },
    "threats": {
        "keywords": [
            "account will be suspended", "account will be closed",
            "legal action", "your account has been compromised",
            "unauthorized access", "suspicious activity detected",
            "your account will be locked", "failure to comply",
            "immediate termination", "penalty", "fine",
            "violation of", "you have violated",
        ],
        "severity": "high",
    },
    "credential_request": {
        "keywords": [
            "verify your account", "confirm your identity",
            "update your payment", "verify your password",
            "enter your password", "login credentials",
            "social security number", "credit card number",
            "bank account details", "confirm your billing",
            "validate your account", "re-enter your password",
            "provide your username", "submit your login",
        ],
        "severity": "high",
    },
    "reward_scam": {
        "keywords": [
            "you have won", "congratulations", "claim your prize",
            "you've been selected", "exclusive offer", "free gift",
            "lottery winner", "inheritance", "unclaimed funds",
            "million dollars", "beneficiary", "congratulations you",
        ],
        "severity": "medium",
    },
    "impersonation": {
        "keywords": [
            "dear customer", "dear user", "dear account holder",
            "valued customer", "dear sir", "dear madam",
            "esteemed customer", "trusted customer",
        ],
        "severity": "low",
    },
}

SUSPICIOUS_PATTERNS = [
    (re.compile(r"click\s+(here|below|this\s+link)", re.I), "Call to action"),
    (re.compile(r"do\s+not\s+(share|tell|forward)", re.I), "Secrecy request"),
    (re.compile(r"(password|passwd|pwd)\s*[:=]", re.I), "Credential prompt"),
    (re.compile(r"(cc|credit\s*card)\s*[:=]?\s*\d{4}", re.I), "Card number pattern"),
    (re.compile(r"\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b", re.I), "SSN pattern"),
    (re.compile(r"wire\s+transfer", re.I), "Payment instruction"),
    (re.compile(r"(western\s+union|money\s+gram)", re.I), "Money transfer"),
    (re.compile(r"bitcoin|crypto\s+wallet|btc\s+address", re.I), "Crypto request"),
]


class SocialEngineeringDetector:
    """Detect social engineering tactics in email text via rules."""

    def detect(self, text: str) -> list[SEResult]:
        results = []
        lower_text = text.lower()

        for category, config in KEYWORD_RULES.items():
            matched_kw = []
            for kw in config["keywords"]:
                if kw.lower() in lower_text:
                    matched_kw.append(kw)

            if matched_kw:
                results.append(
                    SEResult(
                        category=category,
                        matched_keywords=matched_kw,
                        severity=config["severity"],
                    )
                )

        matched_patterns = []
        for pattern, desc in SUSPICIOUS_PATTERNS:
            if pattern.search(text):
                matched_patterns.append(desc)

        if matched_patterns:
            results.append(
                SEResult(
                    category="suspicious_patterns",
                    matched_patterns=matched_patterns,
                    severity="medium",
                )
            )

        return results

    def aggregate_risk(self, results: list[SEResult]) -> int:
        score = 0
        severity_map = {"low": 5, "medium": 10, "high": 15}
        for r in results:
            base = severity_map.get(r.severity, 5)
            score += base + len(r.matched_keywords) * 3 + len(r.matched_patterns) * 4
        return min(score, 100)
