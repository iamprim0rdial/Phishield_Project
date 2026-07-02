def normalize(score, max_score=100):
    return min(score, max_score)


def calculate_final_score(rule_score, intel_score, ai_score):
    """
    Weighted scoring model
    """
    final = (
        rule_score * 0.3 +
        intel_score * 0.3 +
        ai_score * 0.4
    )
    return round(min(final, 100), 2)


def generate_verdict(score):
    if score >= 70:
        return "PHISHING 🚨"
    elif score >= 40:
        return "SUSPICIOUS ⚠️"
    else:
        return "SAFE ✅"