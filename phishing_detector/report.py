"""Report generator for terminal output."""

import json
from phishing_detector.url_analyzer.scorer import RiskReport


RISK_COLORS = {
    "high": "\033[91m",
    "medium": "\033[93m",
    "low": "\033[92m",
}
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"


def format_url_report(report: RiskReport) -> str:
    color = RISK_COLORS.get(report.risk_level, "")
    lines = [
        "",
        f"{BOLD}{'=' * 60}{RESET}",
        f"{BOLD}  URL PHISHING ANALYSIS REPORT{RESET}",
        f"{'=' * 60}",
        "",
        f"  {BOLD}URL:{RESET}       {report.url}",
        f"  {BOLD}Risk Score:{RESET} {color}{report.risk_score}/100{RESET}",
        f"  {BOLD}Risk Level:{RESET} {color}{report.risk_level.upper()}{RESET}",
        "",
    ]

    if report.signals:
        lines.append(f"  {BOLD}Signals Detected:{RESET}")
        for s in report.signals:
            lines.append(f"    [{color}!{RESET}] {s}")
        lines.append("")

    if report.reputation:
        lines.append(f"  {BOLD}Reputation Check:{RESET}")
        for rep in report.reputation:
            status = "FLAGGED" if rep.get("is_known_phishing") else "clean"
            src = rep.get("source", "unknown")
            err = rep.get("error", "")
            if err:
                lines.append(f"    {DIM}{src}: {err}{RESET}")
            else:
                lines.append(
                    f"    {src}: {status} "
                    f"({rep.get('positives', 0)}/{rep.get('total_engines', 0)} engines)"
                )
        lines.append("")

    lines.append(f"{'=' * 60}")
    return "\n".join(lines)


def format_email_report(
    email_data: dict,
    url_reports: list[dict],
    social_results: list[dict],
    se_score: int,
) -> str:
    lines = [
        "",
        f"{BOLD}{'=' * 60}{RESET}",
        f"{BOLD}  EMAIL PHISHING ANALYSIS REPORT{RESET}",
        f"{'=' * 60}",
        "",
        f"  {BOLD}Subject:{RESET}  {email_data.get('subject', '')}",
        f"  {BOLD}From:{RESET}     {email_data.get('from', '')}",
        f"  {BOLD}To:{RESET}       {email_data.get('to', '')}",
        f"  {BOLD}Date:{RESET}     {email_data.get('date', '')}",
        "",
    ]

    auth = email_data.get("auth", {})
    lines.append(f"  {BOLD}Email Authentication:{RESET}")
    for field_name in ("spf", "dkim", "dmarc"):
        val = auth.get(field_name, "")
        passed = auth.get(f"{field_name}_pass")
        if passed is True:
            icon = "\033[92mPASS\033[0m"
        elif passed is False:
            icon = "\033[91mFAIL\033[0m"
        else:
            icon = "\033[93mN/A\033[0m"
        lines.append(f"    {field_name.upper():>6}: {icon}  {val}")
    lines.append("")

    if email_data.get("reply_to"):
        lines.append(
            f"  {BOLD}Reply-To:{RESET}  {email_data['reply_to']}  "
            f"\033[93m[differs from From]\033[0m"
        )
        lines.append("")

    if social_results:
        lines.append(f"  {BOLD}Social Engineering Signals:{RESET}")
        for sr in social_results:
            sev = sr.get("severity", "low")
            cat = sr.get("category", "")
            color = RISK_COLORS.get(sev, "")
            kw = sr.get("matched_keywords", [])
            pats = sr.get("matched_patterns", [])
            lines.append(f"    [{color}{sev.upper()}{RESET}] {cat}")
            for k in kw:
                lines.append(f"      - keyword: \"{k}\"")
            for p in pats:
                lines.append(f"      - pattern: {p}")
        lines.append(f"  SE Risk Score: {se_score}/100")
        lines.append("")

    if url_reports:
        lines.append(f"  {BOLD}Extracted URL Analysis:{RESET}")
        for ur in url_reports:
            score = ur.get("risk_score", 0)
            level = ur.get("risk_level", "low")
            color = RISK_COLORS.get(level, "")
            lines.append(
                f"    {ur.get('url', '')[:70]}  "
                f"{color}[{score}/100 - {level.upper()}]{RESET}"
            )
            for sig in ur.get("signals", []):
                lines.append(f"      - {sig}")
        lines.append("")

    lines.append(f"{'=' * 60}")
    return "\n".join(lines)


def to_json(data: dict) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False)
