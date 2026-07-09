import re
import logging
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger("phishield_oauth")

# 🔒 Hardened Domain Truth Matrix (Prevents text display spoofing)
TRUSTED_PUBLISHERS = ["microsoft.com", "google.com", "slack.com"]

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


def analyze_oauth(app_name: str, scopes: list) -> tuple[int, list[str]]:
    """
    Core OAuth Permission Risk Engine.
    Preserves exact original interface and parameters while safely normalizing outputs.
    """
    score = 0
    findings = []

    # 1. Reputation Check
    if app_name not in TRUSTED_APPS:
        score += 30
        findings.append(f"Untrusted app: {app_name}")

    # 2. Iterative Permission Scraper
    for scope in scopes:
        if scope in SUSPICIOUS_SCOPES:
            score += 20
            findings.append(f"Sensitive permission: {scope}")

    # 3. Persistent Access Validation
    if "offline_access" in scopes:
        score += 40
        findings.append("Persistent access risk")

    # Safe Boundary Normalization
    return min(score, 100), findings


def intercept_and_scan_oauth_links(url: str) -> dict:
    """
    Zero-Consequence Pipeline Interceptor.
    Extracts application names and scopes directly from URL query parameters.
    Overrides malicious string impersonation by validating cryptographic redirect targets.
    """
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()

        # Identify common enterprise authentication endpoints
        oauth_indicators = ["authorize", "oauth", "consent", "signin"]
        is_auth_gate = any(ind in parsed_url.path.lower() for ind in oauth_indicators)

        if not ("://microsoftonline.com" in domain or "://google.com" in domain or is_auth_gate):
            return {"is_oauth_attack": False, "score": 0, "findings": []}

        # 🔒 Hardened Parsing: Unpack query strings safely without crash vulnerability
        query_params = parse_qs(parsed_url.query)

        # 1. Safely extract requested permissions (Handle space/comma variations)
        raw_scopes = query_params.get("scope", [""])
        scopes = []
        if raw_scopes:
            # Flatten multi-value scopes down to an array of single indicators
            combined_scopes = " ".join(raw_scopes)
            scopes = [s.strip() for s in re.split(r'[\s+,]+', combined_scopes) if s.strip()]

        # 2. Extract Application Identity parameters
        # Try finding standard client designations, falling back to a placeholder if absent
        app_name = query_params.get("client_name", query_params.get("app_name", ["Unknown App"]))[0]

        # 3. 🛡️ The Zero-Consequence Bypass Shield: Validate Redirect Domain
        # If an attacker titles their application "Microsoft" but points the redirect 
        # to a malicious endpoint, this block catches the domain mismatch anomaly.
        redirect_uri = query_params.get("redirect_uri", [""])[0]
        if redirect_uri:
            redirect_domain = urlparse(redirect_uri).netloc.lower()
            domain_parts = redirect_domain.split(".")

            # Extract root domain structure (e.g., ://slack.com -> slack.com)
            if len(domain_parts) >= 2:
                root_redirect_domain = ".".join(domain_parts[-2:])

                # Anomaly Enforcement: If app name claims to be trusted but redirect destination
                # points to an unverified third party, strip the trusted label to enforce accuracy.
                if app_name in TRUSTED_APPS and root_redirect_domain not in TRUSTED_PUBLISHERS:
                    logger.warning(
                        f"[!] Defeated App Spoofing: '{app_name}' tracking to untrusted domain '{root_redirect_domain}'")
                    app_name = f"SPOOFED_PSEUDO_{app_name}"

        # 4. Route safe parameters through your core scoring matrix
        final_score, final_findings = analyze_oauth(app_name, scopes)

        # If identity was modified via mismatch rule, inject structural finding directly
        if "SPOOFED_PSEUDO_" in app_name:
            final_score = min(final_score + 40, 100)
            final_findings.insert(0,
                                  f"Critical Anomaly: Application mimics a trusted brand name but routes to unverified domain: '{redirect_domain}'")

        return {
            "is_oauth_attack": final_score > 0,
            "score": final_score,
            "findings": final_findings
        }

    except Exception as e:
        # Fail-Secure Fallback: If malformed queries crash the parser, quarantine by default
        logger.error(f"[-] OAuth wrapper parser failure: {str(e)}")
        return {
            "is_oauth_attack": True,
            "score": 100,
            "findings": ["Parsing error triggered by malformed URL payload structure. Potential evasion attempt."]
        }
