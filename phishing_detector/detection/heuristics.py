"""
Rule-based heuristic engine.

This module inspects raw email text (headers + body pasted together, or
just the body) and produces a list of (reason, weight) findings. Each
finding contributes to an overall heuristic risk score between 0 and 100.
"""

import re

URGENCY_WORDS = [
    "urgent", "immediately", "verify your account", "suspended", "act now",
    "limited time", "click here", "confirm your identity", "unusual activity",
    "restricted", "final notice", "your account will be closed",
    "password will expire", "unauthorized login", "security alert",
]

MONEY_WORDS = [
    "wire transfer", "gift card", "bitcoin", "crypto", "invoice attached",
    "tax refund", "you have won", "lottery", "prize", "claim your reward",
]

CREDENTIAL_WORDS = [
    "login", "password", "ssn", "social security", "credit card number",
    "bank account", "pin number", "one time password", "otp", "cvv",
]

SUSPICIOUS_TLDS = [".xyz", ".top", ".zip", ".click", ".work", ".gq", ".tk", ".ml", ".cf"]

URL_REGEX = re.compile(r"https?://[^\s\)\]\>\"']+", re.IGNORECASE)
IP_URL_REGEX = re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")


def _find_urls(text):
    return URL_REGEX.findall(text)


def _domain_of(url):
    match = re.search(r"https?://([^/]+)/?", url)
    return match.group(1).lower() if match else ""


def analyze_urls(text):
    findings = []
    urls = _find_urls(text)

    if not urls:
        return findings, urls

    for url in urls:
        domain = _domain_of(url)

        if IP_URL_REGEX.match(url):
            findings.append((f"Link uses a raw IP address instead of a domain: {url}", 25))

        if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
            findings.append((f"Link uses an uncommon/high-risk top-level domain: {domain}", 15))

        if domain.count("-") >= 3:
            findings.append((f"Domain contains many hyphens, a common spoofing trick: {domain}", 8))

        if len(domain) > 35:
            findings.append((f"Unusually long domain name: {domain}", 8))

        if re.search(r"(paypal|amazon|apple|microsoft|google|bank|netflix)", domain) and not re.search(
            r"^(www\.)?(paypal|amazon|apple|microsoft|google|netflix)\.com$", domain
        ):
            findings.append((f"Domain mimics a trusted brand name but is not the real domain: {domain}", 20))

    # Mismatched display text vs actual href, e.g. "www.paypal.com (http://evil.tk/x)"
    if re.search(r"(www\.[a-z0-9.-]+\.[a-z]{2,})\s*\(https?://", text, re.IGNORECASE):
        findings.append(("Link text shows one domain but points to a different URL", 20))

    return findings, urls


def analyze_keywords(text_lower):
    findings = []

    urgency_hits = [w for w in URGENCY_WORDS if w in text_lower]
    if urgency_hits:
        findings.append((f"Uses urgency/pressure language ({', '.join(urgency_hits[:3])})", 10 + 3 * min(len(urgency_hits), 3)))

    money_hits = [w for w in MONEY_WORDS if w in text_lower]
    if money_hits:
        findings.append((f"Mentions money/reward bait ({', '.join(money_hits[:3])})", 10 + 3 * min(len(money_hits), 3)))

    cred_hits = [w for w in CREDENTIAL_WORDS if w in text_lower]
    if cred_hits:
        findings.append((f"Requests sensitive credentials ({', '.join(cred_hits[:3])})", 12 + 3 * min(len(cred_hits), 3)))

    if "dear customer" in text_lower or "dear user" in text_lower or "dear valued" in text_lower:
        findings.append(("Generic greeting instead of your actual name", 8))

    if re.search(r"attach(ed|ment)", text_lower) and re.search(r"\.(zip|exe|scr|js|html?)\b", text_lower):
        findings.append(("References a risky attachment type (.zip/.exe/.scr/.js)", 15))

    return findings


def analyze_sender(sender_text, body_text):
    findings = []
    if not sender_text:
        return findings

    sender_lower = sender_text.lower()
    emails_in_sender = EMAIL_REGEX.findall(sender_text)

    # free-mail sender pretending to be a company
    free_domains = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com"]
    company_hint = re.search(r"(support|security|billing|admin|account|no-?reply)@", sender_lower)
    if emails_in_sender and company_hint:
        domain = emails_in_sender[0].split("@")[-1].lower()
        if any(domain.endswith(fd) for fd in free_domains):
            findings.append((f"'Official' looking sender uses a free email provider: {emails_in_sender[0]}", 20))

    # display name domain mismatch e.g. "Apple Support <randomstuff@xyz.tk>"
    if emails_in_sender:
        domain = emails_in_sender[0].split("@")[-1].lower()
        if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
            findings.append((f"Sender address domain uses a high-risk TLD: {domain}", 15))

    return findings


def heuristic_score(sender, subject, body):
    """
    Returns (score 0-100, list_of_reason_strings, list_of_urls_found)
    """
    full_text = f"{subject or ''}\n{body or ''}"
    text_lower = full_text.lower()

    findings = []
    findings += analyze_sender(sender, body)
    findings += analyze_keywords(text_lower)
    url_findings, urls = analyze_urls(full_text)
    findings += url_findings

    raw_score = sum(weight for _, weight in findings)
    score = min(100, raw_score)

    reasons = [reason for reason, _ in findings]
    if not reasons:
        reasons = ["No common phishing indicators were detected by the rule engine."]

    return score, reasons, urls
