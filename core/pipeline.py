from core.scoring import calculate_final_score
from detection.rules import run_predator_analysis
from security.cdr_engine import sanitize_email
from analyzer.link_extractor import extract_links
from analyzer.ai_fusion import analyze_with_context
from sandbox.sandbox_hook import run_sandbox


def run_pipeline(raw_email, user="unknown", metadata=None):
    results = {}

    # Setup data
    sender = metadata.get("from", "unknown") if metadata else "unknown"
    email_text = metadata.get("body", "") if metadata else ""

    # 1. CDR Sanitization
    safe_body = sanitize_email(email_text)

    # 2. Link Extraction (Handle Bytes Error)
    scan_target = email_text
    if isinstance(scan_target, bytes): scan_target = scan_target.decode(errors='ignore')
    links = extract_links(scan_target)

    # 3. Predator Engine
    predator_results = run_predator_analysis(links, "", email_text)

    # 4. Sandbox & AI Fusion
    ai_results = []
    for link in links:
        url = link.get('href', '')
        if not url.startswith("http"): continue
        s_score, s_findings, s_text = run_sandbox(url)
        verdict, reason = analyze_with_context(url, email_text, page_text=s_text)
        ai_results.append(f"{url} → {verdict}: {reason}")

    # 5. Packing for Scoring
    results = {
        "from": sender,
        "body": email_text,
        "ai": ai_results,
        "predator_analysis": predator_results,
        "links": links
    }

    # Final Verdict
    final_score, verdict, findings = calculate_final_score(results)

    return {
        "score": final_score,
        "verdict": verdict,
        "findings": findings,
        "safe_body": safe_body,
        "ai_analysis": ai_results
    }