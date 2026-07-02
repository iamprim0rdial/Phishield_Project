import re
import requests
import tldextract
import whois
import random
from datetime import datetime
from bs4 import BeautifulSoup
from rapidfuzz import fuzz

# --- PERFORMANCE FIX ---
extractor = tldextract.TLDExtract(suffix_list_urls=None)

# --- CONFIG ---
TRUSTED_DOMAINS = ["microsoft.com", "office.com", "google.com", "paypal.com", "amazon.com", "apple.com"]
SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly"]

HEADERS_POOL = [
    {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
    {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"}
]

# --- WHOIS CACHE (PERFORMANCE BOOST) ---
whois_cache = {}

# --- WHOIS AGE ---
def get_domain_age_days(domain):
    if domain in whois_cache:
        return whois_cache[domain]

    try:
        w = whois.whois(domain)
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            age = (datetime.now() - creation_date).days
            whois_cache[domain] = age
            return age

    except:
        whois_cache[domain] = -1
        return -1

    whois_cache[domain] = 1000
    return 1000


# --- SAFE REDIRECT TRACE ---
def trace_url_chain_safe(original_url):
    chain = [original_url]

    if not original_url.startswith("http"):
        return chain

    headers = random.choice(HEADERS_POOL)

    try:
        response = requests.head(
            original_url,
            headers=headers,
            allow_redirects=True,
            timeout=3
        )

        for resp in response.history:
            chain.append(resp.url)

        chain.append(response.url)

    except:
        try:
            response = requests.get(
                original_url,
                headers=headers,
                stream=True,
                timeout=3
            )
            response.close()
            chain.append(response.url)
        except:
            pass

    return list(dict.fromkeys(chain))


# --- MAIN ENGINE ---
def run_predator_analysis(links, email_html, email_text):
    cat_scores = {"deception": 0, "infrastructure": 0, "behavior": 0, "intel": 0}
    findings = []

    seen_domains = set()
    matched_brands = set()

    soup = BeautifulSoup(email_html, "html.parser")

    # --- FORM DETECTION ---
    for form in soup.find_all("form"):
        action = form.get("action", "")
        if action:
            reg_domain = extractor(action).registered_domain
            if reg_domain and reg_domain not in TRUSTED_DOMAINS:
                cat_scores["deception"] += 60
                findings.append(f"[Deception] Data Exfiltration: Untrusted Form Target '{reg_domain}'")

    # --- LINK ANALYSIS ---
    raw_urls = [link.get('href', '') for link in links if link.get('href', '').startswith("http")]

    for original_url in raw_urls:

        # Tracking detection
        if any(x in original_url.lower() for x in ["pixel", "track", "log?id="]):
            cat_scores["behavior"] += 25
            findings.append("[Behavior] Tracking Pixel Detected")

        chain = trace_url_chain_safe(original_url)

        # Protocol downgrade
        if original_url.startswith("https://") and any(u.startswith("http://") for u in chain):
            cat_scores["behavior"] += 30
            findings.append("[Behavior] Protocol Downgrade Detected")

        for hop_url in chain:
            ext = extractor(hop_url)
            domain = f"{ext.domain}.{ext.suffix}".lower()

            if not domain or domain in seen_domains:
                continue

            seen_domains.add(domain)

            # SHORTENER DETECTION
            if any(short in domain for short in SHORTENERS):
                cat_scores["deception"] += 35
                findings.append(f"[Deception] URL Shortener Used: '{domain}'")

            # WHOIS INTEL
            age = get_domain_age_days(domain)

            if 0 <= age < 14:
                cat_scores["intel"] += 50
                findings.append(f"[Intel] Newly Registered Domain: '{domain}' ({age} days old)")

            elif age == -1 and domain not in TRUSTED_DOMAINS:
                cat_scores["intel"] += 40
                findings.append(f"[Intel] WHOIS Obscured: '{domain}'")

            # HOMOGLYPH CHECK
            try:
                if "xn--" in domain or domain.encode('ascii').decode() != domain:
                    cat_scores["deception"] += 45
                    findings.append(f"[Deception] IDN Homoglyph Attack: '{domain}'")
            except:
                pass

            # FUZZY BRAND SPOOFING
            for brand in ["microsoft", "paypal", "google", "amazon", "office"]:
                if brand not in matched_brands:
                    if fuzz.partial_ratio(brand, domain) > 85 and domain not in TRUSTED_DOMAINS:
                        cat_scores["deception"] += 50
                        findings.append(f"[Deception] Brand Spoofing: '{domain}' targets '{brand.upper()}'")
                        matched_brands.add(brand)

    # --- LINK MISMATCH ---
    for link in links:
        visible_text = (link.get("text") or "").strip().lower()
        href = (link.get("href") or "").strip().lower()

        if visible_text and href.startswith("http"):
            vis_domain = extractor(visible_text).registered_domain
            act_domain = extractor(href).registered_domain

            if vis_domain and act_domain and vis_domain != act_domain:
                cat_scores["deception"] += 45
                findings.append(f"[Deception] Link Mismatch: UI says '{vis_domain}' but leads to '{act_domain}'")

    return {
        "score_map": cat_scores,
        "list": list(set(findings))
    }


def analyze_identity_risk(sender_mail, email_body, ai_analysis):
    risk_points = 0
    findings = []

    sender_mail = sender_mail.lower()
    body = email_body.lower()
    ai_low = ai_analysis.lower()

    # 1. Broad Freemail Check
    is_freemail = any(f in sender_mail for f in ["@gmail", "@yahoo", "@outlook", "@hotmail", "@live"])

    # 2. Expanded Brand & Financial Keywords
    critical_keywords = ["norton", "mcafee", "invoice", "refund", "billing", "payment", "microsoft", "paypal",
                         "it support"]
    found_brands = [k for k in critical_keywords if k in body]

    # 3. The Logic Bridge
    if is_freemail and found_brands:
        risk_points = 75  # High signal for Vishing/Scams
        brand_name = found_brands[0].upper()
        findings.append(f"[Identity] Brand Alert: '{brand_name}' mentioned from a personal Freemail account.")

    # 4. Legit Employee/Personal Mail Bypass (Anti-False Positive)
    # Agar AI 'safe' bol raha hai aur koi dangerous financial urgency nahi hai
    urgency_keywords = ["call now", "urgent", "immediately", "unauthorized", "action required"]
    if "safe" in ai_low and not any(u in body for u in urgency_keywords):
        risk_points = 0  # Neutralize for normal internal/personal talk
        findings = []  # Clear findings if it's legit

    return risk_points, findings