from detection.rules import analyze_identity_risk


def calculate_final_score(results):
    sender_mail = results.get("from", "").lower()
    email_body = results.get("body", "").lower()
    ai_analysis = str(results.get("ai", [])).lower()

    predator = results.get("predator_analysis", {"score_map": {}, "list": []})
    cat_scores = predator.get("score_map", {})
    findings = predator.get("list", [])

    # Vector Risks
    tech_risk = (cat_scores.get("intel", 0) + cat_scores.get("behavior", 0)) / 100
    vis_risk = cat_scores.get("deception", 0) / 100

    # Identity & Content Risk
    id_risk_val, id_findings = analyze_identity_risk(sender_mail, email_body, ai_analysis)
    findings.extend(id_findings)

    # AI Risk
    ctx_risk = 0.1
    if "phishing" in ai_analysis or "scam" in ai_analysis:
        ctx_risk = 0.95
    elif "suspicious" in ai_analysis:
        ctx_risk = 0.5
    elif "safe" in ai_analysis:
        ctx_risk = 0.0

    # Dynamic Math
    if ctx_risk == 0.0:
        final_score = int(((tech_risk * 0.5) + (vis_risk * 0.5) + ((id_risk_val / 100) * 0.2)) * 100)
    else:
        final_score = int(max(tech_risk, vis_risk, ctx_risk, (id_risk_val / 100)) * 100)
        if (tech_risk + vis_risk) > 0.4: final_score = max(final_score, 85)

    # Safety Nets
    if len(results.get("links", [])) == 0 and ctx_risk == 0.0: final_score = min(final_score, 25)
    if id_risk_val >= 60 and ctx_risk >= 0.5: final_score = max(final_score, 88)

    final_score = min(final_score, 100)
    verdict = "MALICIOUS" if final_score >= 80 else "SUSPICIOUS" if final_score >= 45 else "SAFE"

    return final_score, verdict, list(set(findings))