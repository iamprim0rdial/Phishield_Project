import dns.resolver
import whois
import requests
from urllib.parse import urlparse
import datetime

SUSPICIOUS_TLDS = ["xyz", "top", "tk", "ml", "ga"]

def analyze_intel(url):
    score = 0
    findings = []

    domain = urlparse(url).netloc

    # TLD
    tld = domain.split(".")[-1]
    if tld in SUSPICIOUS_TLDS:
        score += 40
        findings.append(f"Suspicious TLD: .{tld}")

    # DNS
    try:
        ip = dns.resolver.resolve(domain, "A")[0].to_text()
        findings.append(f"Resolved IP: {ip}")
    except:
        score += 30
        findings.append("DNS resolution failed")

    # WHOIS
    try:
        w = whois.whois(domain)
        creation = w.creation_date

        if isinstance(creation, list):
            creation = creation[0]

        age = (datetime.datetime.now() - creation).days

        if age < 30:
            score += 60
            findings.append(f"Very new domain ({age} days)")
    except:
        findings.append("WHOIS failed")

    # PhishTank
    try:
        r = requests.get(
            f"http://checkurl.phishtank.com/checkurl/?url={url}",
            timeout=5
        )
        if "phish" in r.text.lower():
            score += 100
            findings.append("Known phishing (PhishTank)")
    except:
        pass


    return score, findings  # findings contains "DNS resolution failed", "Resolved IP: x.x.x.x", etc.

