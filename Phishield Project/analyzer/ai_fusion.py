import subprocess
from collections import defaultdict
from urllib.parse import urlparse
from datetime import datetime

# -------------------------
# Deduplicate links
def deduplicate_links(links):
    link_map = defaultdict(list)
    for link in links:
        href = link['href'].lower()
        link_map[href].append(link)

    deduped = []
    for href, entries in link_map.items():
        combined_entry = entries[0].copy()
        combined_texts = list({e['text'] for e in entries})
        combined_entry['text'] = ", ".join(combined_texts)
        deduped.append(combined_entry)
    return deduped

# -------------------------
# Weighted AI score
def weighted_ai_score(ai_results, weights=None):
    if weights is None:
        weights = [1] * len(ai_results)
    score = sum((1 if is_phish else 0) * w for (is_phish, _), w in zip(ai_results, weights))
    return score / sum(weights)

# -------------------------
# DNS scoring
def dns_score(link_info):
    score = 0
    tld_suspicious = ['.xyz', '.tk', '.ga', '.cf', '.gq']
    href = link_info['href']
    parsed = urlparse(href)

    if any(parsed.netloc.endswith(tld) for tld in tld_suspicious):
        score += 30
    if link_info.get('dns_failed', False):
        score += 20
    if link_info.get('resolved_ip') != link_info.get('expected_ip'):
        score += 20

    return score

# -------------------------
# PhishTank scoring
def phishtank_score(link_info):
    if link_info.get('known_phish', False):
        return 50
    return 0

# -------------------------
# Advanced email analysis
def analyze_email_advanced(email_links, ai_outputs=None):
    ai_outputs = ai_outputs or {}
    deduped_links = deduplicate_links(email_links)

    total_score = 0
    findings = []

    for link in deduped_links:
        href = link['href']
        ai_result = ai_outputs.get(href, [(False, "No AI data")])
        ai_weighted = weighted_ai_score(ai_result)

        score = ai_weighted * 50
        score += dns_score(link)
        score += phishtank_score(link)
        score = min(score, 100)
        total_score += score

        findings.append({
            'link': href,
            'score': round(score, 2),
            'ai_details': ai_result,
            'dns_details': {k: link.get(k) for k in ['dns_failed', 'resolved_ip', 'expected_ip'] if k in link},
            'known_phish': link.get('known_phish', False)
        })

    final_score = min(total_score / len(deduped_links), 100) if deduped_links else 0
    verdict = "PHISHING 🚨" if final_score >= 50 else "SAFE ✅"

    return {
        'final_score': final_score,
        'verdict': verdict,
        'findings': findings
    }

# -------------------------
# Formatted email report
def generate_email_report(analysis_result, email_meta):
    report_lines = []
    report_lines.append("=== PHISHIELD EMAIL ANALYSIS REPORT ===")
    report_lines.append(f"From: {email_meta.get('from')}")
    report_lines.append(f"Subject: {email_meta.get('subject')}")
    report_lines.append(f"Date: {email_meta.get('date', datetime.now())}")
    report_lines.append(f"Final Score: {analysis_result['final_score']}/100")
    report_lines.append(f"Verdict: {analysis_result['verdict']}")
    report_lines.append("\n--- Findings per link ---")

    for f in analysis_result['findings']:
        report_lines.append(f"\nLink: {f['link']}")
        report_lines.append(f"Score: {f['score']}/100")
        report_lines.append(f"AI Details: {f['ai_details']}")
        if f['dns_details']:
            report_lines.append(f"DNS Info: {f['dns_details']}")
        if f['known_phish']:
            report_lines.append("Known phishing link: YES")

    report_lines.append("\n======================================")
    return "\n".join(report_lines)

# -------------------------
# Original AI-Fusion call
def analyze_with_context(domain,url,text):
    print(f"[AI-FUSION] Analyzing: {domain}")

    prompt = f"""
You are an advanced phishing detection AI.

Analyze the following:

Domain: {domain}

URL: {url}

Page Text:
{text[:2000]}

Decide:
1. Is this a phishing page? (YES / NO / SUSPICIOUS)
2. Give a short reason (1-2 lines)

Focus on:
- Fake login pages
- Brand impersonation
- Suspicious domain patterns
- Mismatch between domain and branding
- Suspicious domain (typos, unusual TLDs)

Be confident. Do NOT say "cannot determine".
"""

    try:
        result = subprocess.run(
            ["ollama", "run", "llava"],
            input=f"{prompt}",
            text=True,
            capture_output=True,
            encoding="utf-8",
            errors="ignore"
        )

        output = result.stdout
        print("[AI-FUSION RESULT]", output)

        return output

    except Exception as e:
        print("[ERROR AI FUSION]", e)
        return None