import dns.resolver
import whois
import requests
from urllib.parse import urlparse
import datetime

# -------------------------
# CONFIG
SUSPICIOUS_TLDS = ["xyz", "top", "tk", "ml", "ga", "click", "shop", "info"]
WHOIS_AGE_THRESHOLD = 30  # Days: anything younger is high risk
TIMEOUT = 5


# -------------------------
# 🛠️ HELPERS

def safe_dns_lookup(domain):
    try:
        # Use a specific resolver to avoid system-level hangs
        resolver = dns.resolver.Resolver()
        resolver.lifetime = TIMEOUT
        answers = resolver.resolve(domain, "A")
        return str(answers[0]), None
    except Exception as e:
        return None, f"DNS Lookup Failed: {str(e)}"


def safe_whois_lookup(domain):
    try:
        # Some TLDs don't support WHOIS well; we wrap in a broad try/except
        w = whois.whois(domain)
        creation = w.creation_date

        if isinstance(creation, list):
            creation = creation[0]

        if creation:
            age = (datetime.datetime.now() - creation).days
            return age, None
        return None, "WHOIS data hidden or unavailable"
    except Exception:
        return None, "WHOIS connection timed out"


# -------------------------
# 🔍 MAIN ANALYSIS

def analyze_intel(url):
    """
    Performs infrastructure-level checks on a URL.
    Returns: (score, findings)
    """
    score = 0
    findings = []

    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    if ":" in domain: domain = domain.split(":")[0]  # Remove port

    if not domain:
        return 0, []

    # 1. TLD Analysis
    tld = domain.split(".")[-1]
    if tld in SUSPICIOUS_TLDS:
        score += 25
        findings.append(f"High-risk TLD: .{tld}")

    # 2. Domain Age (The most powerful signal)
    age, error = safe_whois_lookup(domain)
    if age is not None:
        if age < WHOIS_AGE_THRESHOLD:
            score += 50
            findings.append(f"Newly registered domain ({age} days old)")
        elif age < 180:  # Less than 6 months
            score += 15
            findings.append("Relatively young domain (< 6 months)")
    else:
        # If WHOIS fails on a non-trusted domain, it's a minor red flag
        findings.append(f"Intel Note: {error}")

    # 3. DNS Verification
    ip, dns_error = safe_dns_lookup(domain)
    if dns_error:
        # Often phishers use domains that get taken down quickly
        score += 20
        findings.append("Domain has no valid A-record (Dormant/Dead)")
    else:
        # Check if IP is a known malicious range (optional expansion)
        pass

    return min(score, 100), findings