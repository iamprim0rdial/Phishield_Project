import Levenshtein
from utils.helpers import get_domain

suspicious_keywords = [
    "urgent",
    "verify your account",
    "password reset",
    "bank",
    "login immediately",
    "click below"
]

trusted_domains = [
    "google.com",
    "paypal.com",
    "microsoft.com",
    "amazon.com",
    "bank.com"
]
suspicious_tlds = ["xyz", "top", "click", "ru"]

def detect_suspicious_content(text):
    score = 0
    findings = []

    for keyword in suspicious_keywords:
        if keyword.lower() in text.lower():
            score += 20
            findings.append(f"Keyword detected: {keyword}")

    return score, findings

def detect_link_mismatch(links):
    score = 0
    findings = []

    for link in links:
        if isinstance(link, dict):
            href = link["href"]
            text = link["text"]

            # If visible text looks like a URL but is different
            if text.startswith("http") and text not in href:
                score += 40
                findings.append(f"Mismatch: text={text} href={href}")

    return score, findings



def detect_lookalike_domain(links):
    score = 0
    findings = []

    for link in links:
        url = link["href"] if isinstance(link, dict) else link
        domain = get_domain(url)

        for trusted in trusted_domains:
            distance = Levenshtein.distance(domain, trusted)

            # if very similar but not same → suspicious
            if 0 < distance <= 2:
                score += 50
                findings.append(f"Lookalike domain: {domain} ~ {trusted}")

    return score, findings


def detect_suspicious_tld(links):
    score = 0
    findings = []

    for link in links:
        url = link["href"] if isinstance(link, dict) else link

        if "." in url:
            tld = url.split(".")[-1].split("/")[0]

            if tld in suspicious_tlds:
                score += 30
                findings.append(f"Suspicious TLD: .{tld}")

    return score, findings