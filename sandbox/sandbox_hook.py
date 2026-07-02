import re

def run_sandbox(url):
    """
    Simulated sandbox analysis (SYNC version)
    Future: Replace with Playwright / headless browser
    """
    behavior_score = 0
    behavior_findings = []
    page_text = ""

    print(f"[SANDBOX] Visiting: {url}")

    # 1. Fake content simulation (for testing)
    if "login" in url:
        page_text += "login password verify account"
        behavior_score += 20
        behavior_findings.append("Login page behavior detected")

    if "secure" in url or "verify" in url:
        page_text += " verify your identity urgently"
        behavior_score += 15
        behavior_findings.append("Urgency / verification pattern")

    if "paypa1" in url or "bank" in url:
        page_text += " enter your bank credentials"
        behavior_score += 25
        behavior_findings.append("Possible credential harvesting")

    # 2. Suspicious patterns in URL
    if re.search(r'\d', url):
        behavior_score += 10
        behavior_findings.append("Numeric domain (possible spoofing)")

    if "-" in url:
        behavior_score += 5
        behavior_findings.append("Hyphenated domain (common in phishing)")

    if len(url) > 50:
        behavior_score += 10
        behavior_findings.append("Long URL (obfuscation attempt)")

    # 3. Redirect simulation
    if "redirect" in url:
        behavior_score += 20
        behavior_findings.append("Suspicious redirect behavior")

    # 4. Final normalization
    if behavior_score > 100:
        behavior_score = 100

    print(f"[SANDBOX] Score: {behavior_score}")

    # FIXED: Returning as a tuple (score, list, string)
    return behavior_score, behavior_findings, page_text