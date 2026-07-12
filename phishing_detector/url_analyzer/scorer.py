"""Risk scoring engine combining features and reputation into a 0-100 score."""

from dataclasses import dataclass, field

from phishing_detector.url_analyzer.feature_extractor import URLFeatures
from phishing_detector.url_analyzer.reputation import ReputationResult


@dataclass
class RiskReport:
    url: str
    risk_score: int = 0
    risk_level: str = "low"
    signals: list = field(default_factory=list)
    reputation: list = field(default_factory=list)
    features: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "signals": self.signals,
            "reputation": [r for r in self.reputation],
            "features": self.features,
        }


class RiskScorer:
    """Combines feature analysis and reputation into a 0-100 risk score."""

    def score(
        self,
        features: URLFeatures,
        reputation_results: list[ReputationResult] | None = None,
    ) -> RiskReport:
        report = RiskReport(url=features.url)
        report.features = features.to_dict()
        points = 0

        # --- Feature-based signals ---

        if features.has_ip_address:
            points += 25
            report.signals.append("URL uses IP address instead of domain name")

        if features.length > 120:
            points += 15
            report.signals.append(f"URL is unusually long ({features.length} chars)")
        elif features.length > 75:
            points += 10
            report.signals.append(f"URL is unusually long ({features.length} chars)")

        if features.num_hyphens >= 2:
            points += 8
            report.signals.append(f"Domain contains {features.num_hyphens} hyphens")

        if features.num_special_chars > 5:
            points += 10
            report.signals.append(
                f"High number of special characters ({features.num_special_chars})"
            )

        if features.num_subdomains >= 3:
            points += 12
            report.signals.append(
                f"Excessive subdomains ({features.num_subdomains})"
            )

        if features.num_at_symbols > 0:
            points += 20
            report.signals.append("URL contains @ symbol (credential obfuscation)")

        if features.has_suspicious_tld:
            points += 10
            report.signals.append("Uses a suspicious TLD (.xyz, .top, .tk, etc.)")

        if features.has_shortening_service:
            points += 5
            report.signals.append("URL uses a shortening service")

        if features.has_double_slash_redirect:
            points += 10
            report.signals.append("URL contains double-slash redirect in path")

        if not features.has_https:
            points += 5
            report.signals.append("URL does not use HTTPS")

        if features.num_digits > 5:
            points += 5
            report.signals.append(
                f"Domain contains many digits ({features.num_digits})"
            )

        for match in features.typosquatting_matches:
            points += 15
            report.signals.append(
                f"Possible typosquatting of {match['target']} "
                f"(edit distance: {match['distance']})"
            )

        # --- Reputation signals ---

        if reputation_results:
            for rep in reputation_results:
                report.reputation.append(rep.to_dict())
                if rep.is_known_phishing:
                    points += 30
                    report.signals.append(
                        f"Flagged by {rep.source} "
                        f"({rep.positives}/{rep.total_engines} engines)"
                    )
                elif rep.positives > 0:
                    points += 15
                    report.signals.append(
                        f"Partial detection by {rep.source} "
                        f"({rep.positives}/{rep.total_engines})"
                    )

        report.risk_score = min(points, 100)

        if report.risk_score >= 70:
            report.risk_level = "high"
        elif report.risk_score >= 40:
            report.risk_level = "medium"
        else:
            report.risk_level = "low"

        return report
