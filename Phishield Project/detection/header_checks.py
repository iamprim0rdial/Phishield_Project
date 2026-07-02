def check_authentication(headers):
    score = 0
    findings = []

    auth_results = headers.get("authentication-results", "")

    if "spf=fail" in auth_results.lower():
        score += 40
        findings.append("SPF failed 🚨")

    if "dkim=fail" in auth_results.lower():
        score += 40
        findings.append("DKIM failed 🚨")

    if "dmarc=fail" in auth_results.lower():
        score += 50
        findings.append("DMARC failed 🚨")


    return score, findings

