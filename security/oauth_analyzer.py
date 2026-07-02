SUSPICIOUS_SCOPES = [
    "mail.read",
    "mail.send",
    "files.readwrite",
    "offline_access"
]

TRUSTED_APPS = [
    "Google",
    "Microsoft",
    "Slack"
]


def analyze_oauth(app_name, scopes):
    score = 0
    findings = []

    if app_name not in TRUSTED_APPS:
        score += 30
        findings.append(f"Untrusted app: {app_name}")

    for scope in scopes:
        if scope in SUSPICIOUS_SCOPES:
            score += 20
            findings.append(f"Sensitive permission: {scope}")

    if "offline_access" in scopes:
        score += 40
        findings.append("Persistent access risk")

    return min(score, 100), findings