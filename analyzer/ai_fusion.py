import subprocess
from collections import defaultdict
from urllib.parse import urlparse
import json

# -------------------------
# CONFIG
MAX_RETRIES = 2
TIMEOUT = 25  # Slightly increased for stability


# -------------------------
# Deduplicate links (Professional version)
def deduplicate_links(links):
    """
    Groups links by their destination (href) so the AI only analyzes unique domains.
    """
    link_map = defaultdict(list)
    for link in links:
        href = link.get('href', '').lower().strip()
        if not href: continue
        link_map[href].append(link)

    deduped = []
    for href, entries in link_map.items():
        # Keep the most relevant text description for the AI
        unique_texts = list({e.get('text', '') for e in entries if e.get('text')})
        deduped.append({
            "href": href,
            "text": " | ".join(unique_texts) if unique_texts else href,
            "count": len(entries)
        })
    return deduped


# -------------------------
# 🔍 IMPROVED OUTPUT PARSER
def parse_ai_output(output):
    """
    Robust parsing of LLM response using simple keyword mapping and structured slicing.
    """
    output_lower = output.lower()
    verdict = "Safe"
    explanation = "No suspicious indicators found by AI."

    if "phishing" in output_lower:
        verdict = "Phishing"
    elif "suspicious" in output_lower:
        verdict = "Suspicious"

    # Extract Reason after the 'Reason:' label
    if "reason:" in output_lower:
        try:
            # Case insensitive split
            parts = output.split("Reason:") if "Reason:" in output else output.split("reason:")
            explanation = parts[1].strip()
        except (IndexError, AttributeError):
            explanation = output[:200]
    else:
        explanation = output[:200]

    return verdict, explanation


# -------------------------
# 🧠 ENHANCED PROMPT BUILDER
def build_prompt(domain, url, page_text, email_text):
    """
    Creates a high-context prompt for the LLM to minimize false positives.
    """
    return f"""
    ### ROLE: AN ADVANCED CYBERSECURITY ANALYST AI
    TASK: Determine if the following link in this email context is PHISHING.

    ### EMAIL CONTEXT:
    {email_text[:1200]}

    ### LINK DATA:
    - Domain: {domain}
    - Full URL: {url}

    ### OBSERVED PAGE BEHAVIOR:
    {page_text[:1000]}

    ### EVALUATION CRITERIA:
    1. Is the email creating fake urgency (e.g., "Account suspended")?
    2. Does the link text (e.g., "Click here to login") match a reputable domain?
    3. Is this a brand impersonation (e.g., 'mircosoft.com')?

    ### RESPONSE FORMAT:
    Verdict: <Phishing / Suspicious / Safe>
    Reason: <One sentence explanation>
    
    Focus on:
        - Fake login pages
        - Brand impersonation
        - Suspicious domain patterns
        - Mismatch between domain and branding
        - Typosquatting / homograph attacks
        - Email intent (urgency, fear, reward)

    Be confident. Do NOT say "cannot determine.
    If no URLs are detected, focus 100% on Textual Deception. Analyze the sender's email address against the claimed brand (e.g., Norton from @gmail.com). Flag any mentions of:
    Financial Urgency: (Invoice, Charge, Refund, $ Amount).
    Callback Scams: (Phone numbers, 'Call us immediately').
    Social Engineering: (Fear, Authority, Scarcity).
    Even with 0 links, if the intent is to deceive the user into a phone call or manual action, the verdict MUST be MALICIOUS or SUSPICIOUS.
    """


def analyze_with_context(url, email_text, page_text="No page content available"):
    """
    Main entry point for AI analysis.
    """
    domain = urlparse(url).netloc
    prompt = build_prompt(domain, url, page_text, email_text)

    # Placeholder for actual LLM call (subprocess to ollama or requests to OpenAI)
    # This matches the structure used in your Code Part 2
    for attempt in range(MAX_RETRIES):
        try:
            # Simulated call logic based on your existing code
            result = subprocess.run(
                ["ollama", "run", "llava", prompt],
                input=prompt,
                text=True,
                capture_output=True,
                encoding="utf-8",
                errors="ignore"
            )
            if result.returncode == 0:
                return parse_ai_output(result.stdout)
        except Exception:
            continue

    return "Unknown", "AI Service unavailable"
