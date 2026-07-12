"""CLI entry point for phishing-detector."""

import sys
import argparse

from phishing_detector.url_analyzer import URLFeatureExtractor, ReputationChecker, RiskScorer
from phishing_detector.email_analyzer import EmailParser, SocialEngineeringDetector
from phishing_detector.report import format_url_report, format_email_report, to_json


def analyze_url(url: str, vt_key: str = "", pt_key: str = "", json_out: bool = False):
    extractor = URLFeatureExtractor()
    checker = ReputationChecker(vt_api_key=vt_key, phishtank_api_key=pt_key)
    scorer = RiskScorer()

    features = extractor.extract(url)
    rep_results = checker.check(url)
    report = scorer.score(features, rep_results)

    if json_out:
        print(to_json(report.to_dict()))
    else:
        print(format_url_report(report))


def analyze_email(
    eml_path: str,
    vt_key: str = "",
    pt_key: str = "",
    json_out: bool = False,
):
    parser = EmailParser()
    se_detector = SocialEngineeringDetector()
    url_extractor = URLFeatureExtractor()
    rep_checker = ReputationChecker(vt_api_key=vt_key, phishtank_api_key=pt_key)
    url_scorer = RiskScorer()

    parsed = parser.parse(eml_path)
    email_dict = parsed.to_dict()

    se_results = se_detector.detect(parsed.body_text + " " + parsed.body_html)
    se_score = se_detector.aggregate_risk(se_results)

    url_reports = []
    all_links = parsed.links

    for link in all_links:
        features = url_extractor.extract(link)
        rep = rep_checker.check(link)
        report = url_scorer.score(features, rep)
        url_reports.append(report.to_dict())

    combined_score = min(
        100,
        se_score + sum(r.get("risk_score", 0) for r in url_reports) // max(len(url_reports), 1),
    )

    if json_out:
        output = {
            "email": email_dict,
            "url_reports": url_reports,
            "social_engineering": [r.to_dict() for r in se_results],
            "se_risk_score": se_score,
            "combined_risk_score": combined_score,
        }
        print(to_json(output))
    else:
        print(format_email_report(
            email_dict,
            url_reports,
            [r.to_dict() for r in se_results],
            se_score,
        ))


def main():
    ap = argparse.ArgumentParser(
        prog="phishing-detector",
        description="Phishing URL and Email Analyzer",
    )
    sub = ap.add_subparsers(dest="command", help="Command to run")

    url_p = sub.add_parser("url", help="Analyze a URL")
    url_p.add_argument("url", help="URL to analyze")
    url_p.add_argument("--json", action="store_true", help="Output as JSON")

    email_p = sub.add_parser("email", help="Analyze an .eml file")
    email_p.add_argument("file", help="Path to .eml file")
    email_p.add_argument("--json", action="store_true", help="Output as JSON")

    ap.add_argument("--vt-key", default="", help="VirusTotal API key")
    ap.add_argument("--pt-key", default="", help="PhishTank API key")

    args = ap.parse_args()

    vt_key = args.vt_key
    pt_key = args.pt_key
    json_out = getattr(args, "json", False)

    if args.command == "url":
        analyze_url(args.url, vt_key, pt_key, json_out)
    elif args.command == "email":
        analyze_email(args.file, vt_key, pt_key, json_out)
    else:
        ap.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
