"""
Generates a SOC-analyst-style incident report from a completed scan.

- verdict == "phishing" or "suspicious"  -> True Positive report
- verdict == "safe"                      -> False Positive report
"""

import re
from datetime import datetime

from .heuristics import EMAIL_REGEX, _domain_of, SUSPICIOUS_TLDS, IP_URL_REGEX

REMEDIATION_ACTIONS = [
    "Block the sender's email address and domain at the mail gateway.",
    "Block or sinkhole all URLs/domains found in the email at the web proxy/firewall.",
    "Notify the affected user(s) and instruct them not to click any links or open attachments.",
    "If any link was clicked or credentials entered, force an immediate password reset and review account activity/sign-in logs for the affected account.",
    "Search mail logs to identify whether the same sender/subject/links were sent to other users, and quarantine those copies.",
    "Report the sender/domain to the email provider and, if applicable, to a phishing threat-intel feed.",
    "Add the observed indicators (sender domain, URLs, IPs) to the organization's blocklist/SIEM watchlist.",
    "Conduct brief security-awareness reinforcement with the affected user(s) on recognizing similar lures.",
]


def _extract_entities(sender, body):
    entities = []

    sender_emails = EMAIL_REGEX.findall(sender or "")
    for e in sender_emails:
        entities.append(f"Sender address: {e}")
        domain = e.split("@")[-1]
        entities.append(f"Sender domain: {domain}")

    if not sender_emails and sender:
        entities.append(f"Sender (raw): {sender}")

    url_pattern = re.compile(r"https?://[^\s\)\]\>\"']+", re.IGNORECASE)
    for url in url_pattern.findall(body or ""):
        domain = _domain_of(url)
        if domain:
            entities.append(f"Linked domain: {domain}")

    # de-duplicate while preserving order
    seen = set()
    unique = []
    for item in entities:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique or ["No identifiable sender or link entities were found in the email content."]


def _extract_indicators(sender, urls):
    indicators = []

    for e in EMAIL_REGEX.findall(sender or ""):
        indicators.append(f"IOC (sender email): {e}")

    for url in urls or []:
        indicators.append(f"IOC (URL): {url}")
        domain = _domain_of(url)
        if IP_URL_REGEX.match(url):
            indicators.append(f"IOC (raw-IP link): {url}")
        if domain and any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
            indicators.append(f"IOC (high-risk TLD domain): {domain}")

    return indicators or ["No concrete technical indicators (IOCs) were extracted from this email."]


def generate_report(record, reasons, recipient_username=None):
    """
    record: a ScanHistory model instance
    reasons: list[str] returned by the analyzer
    """
    url_pattern = re.compile(r"https?://[^\s\)\]\>\"']+", re.IGNORECASE)
    urls = url_pattern.findall(f"{record.subject or ''}\n{record.raw_text or ''}")

    is_true_positive = record.verdict in ("phishing", "suspicious")
    time_str = record.created_at.strftime("%d %b %Y, %H:%M:%S UTC")

    if is_true_positive:
        entities = _extract_entities(record.sender, record.raw_text)
        if recipient_username:
            entities = [f"Recipient (mailbox owner): {recipient_username}"] + entities

        classification_reason = (
            f"This email was classified as a phishing/suspicious True Positive with a combined "
            f"risk score of {record.risk_score}/100. The detection engine identified the "
            f"following indicators: " + "; ".join(reasons) + "."
        )

        if record.verdict == "phishing":
            escalation_reason = (
                f"The risk score ({record.risk_score}/100) exceeds the phishing escalation "
                f"threshold (65/100). The email combines credential-harvesting or urgency "
                f"tactics with suspicious link/sender characteristics, indicating a high "
                f"likelihood of real-world harm if left unaddressed. Escalating for containment "
                f"and user notification."
            )
        else:
            escalation_reason = (
                f"The risk score ({record.risk_score}/100) falls in the suspicious range "
                f"(35-64/100). While not conclusively malicious, multiple indicators were "
                f"present. Escalating to a human analyst for manual review and confirmation "
                f"before closing or reclassifying the alert."
            )

        return {
            "classification": "True Positive",
            "time_of_activity": time_str,
            "entities_label": "List of Affected Entities",
            "entities": entities,
            "classification_reason_label": "Reason for Classifying as True Positive",
            "classification_reason": classification_reason,
            "escalation_label": "Reason for Escalating the Alert",
            "escalation_reason": escalation_reason,
            "remediation_label": "Recommended Remediation Actions",
            "remediation_actions": REMEDIATION_ACTIONS,
            "indicators_label": "List of Attack Indicators",
            "indicators": _extract_indicators(record.sender, urls),
        }

    else:
        entities = _extract_entities(record.sender, record.raw_text)
        if recipient_username:
            entities = [f"Recipient (mailbox owner): {recipient_username}"] + entities

        classification_reason = (
            f"This email was classified as a False Positive with a low combined risk score "
            f"of {record.risk_score}/100. Neither the rule-based heuristic engine nor the ML "
            f"text classifier identified credential-harvesting requests, urgency/pressure "
            f"language, suspicious links, or sender-spoofing indicators. Analysis notes: "
            + "; ".join(reasons) + "."
        )

        return {
            "classification": "False Positive",
            "time_of_activity": time_str,
            "entities_label": "List of Related Entities",
            "entities": entities,
            "classification_reason_label": "Reason for Classifying as False Positive",
            "classification_reason": classification_reason,
        }


def report_to_text(report):
    """Render the report dict as a plain-text document (for download)."""
    lines = [
        "=" * 60,
        f"INCIDENT REPORT — {report['classification'].upper()}",
        "=" * 60,
        "",
        f"Time of Activity: {report['time_of_activity']}",
        "",
        f"{report['entities_label']}:",
    ]
    lines += [f"  - {e}" for e in report["entities"]]
    lines += [
        "",
        f"{report['classification_reason_label']}:",
        f"  {report['classification_reason']}",
    ]

    if report["classification"] == "True Positive":
        lines += [
            "",
            f"{report['escalation_label']}:",
            f"  {report['escalation_reason']}",
            "",
            f"{report['remediation_label']}:",
        ]
        lines += [f"  {i+1}. {a}" for i, a in enumerate(report["remediation_actions"])]
        lines += [
            "",
            f"{report['indicators_label']}:",
        ]
        lines += [f"  - {ind}" for ind in report["indicators"]]

    lines += ["", "=" * 60, f"Generated by PhishGuard on {datetime.utcnow().strftime('%d %b %Y, %H:%M:%S UTC')}"]
    return "\n".join(lines)
