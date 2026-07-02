def generate_verdict(score, findings, ai_outputs):
    verdict = "SAFE"

    if score >= 200:
        verdict = "PHISHING 🚨"
    elif score >= 100:
        verdict = "SUSPICIOUS ⚠️"

    for ai in ai_outputs:
        if any("yes" in str(ai).lower() for ai in ai_outputs):
            verdict = "PHISHING 🚨"
        elif ai and "suspicious" in ai.lower():
            verdict = "SUSPICIOUS ⚠️"

    return verdict