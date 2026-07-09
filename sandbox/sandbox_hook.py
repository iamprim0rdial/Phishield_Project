import re
import uuid
import logging
from pathlib import Path
from playwright.sync_api import sync_playwright

logger = logging.getLogger("phishield_sandbox")


def run_sandbox(url: str) -> tuple[int, list[str], str]:
    """
    Hardened Synchronous Sandbox Analysis Engine for PhiShield testing.
    Keeps original system architecture while executing isolated live URL scraping.
    """
    behavior_score = 0
    behavior_findings = []
    page_text = ""

    print(f"[SANDBOX] Visiting: {url}")

    # 1. 🔒 SSRF Prevention: Kill internal routing before opening the browser socket
    forbidden_hosts = ["localhost", "127.0.0.1", "0.0.0.0", "169.254.169.254", "192.168.", "10."]
    if any(host in url for host in forbidden_hosts):
        print(f"[SANDBOX] Blocked: Attempted local network access.")
        return 100, ["SSRF Attack Vector Blocked"], "Blocked access to internal network."

    # 2. 🔍 Static URL Anatomy Heuristics
    if re.search(r'\d', url):
        behavior_score += 10
        behavior_findings.append("Numeric domain (possible spoofing)")

    if "-" in url:
        behavior_score += 5
        behavior_findings.append("Hyphenated domain (common in phishing)")

    if len(url) > 50:
        behavior_score += 10
        behavior_findings.append("Long URL (obfuscation attempt)")

    # 3. 🌐 Isolated Synchronous Browser Execution
    # Session data, cookies, and local directories are cleanly randomized per test
    unique_id = uuid.uuid4().hex
    preview_dir = Path(f"previews/{unique_id}")
    preview_dir.mkdir(parents=True, exist_ok=True)
    screenshot_path = preview_dir / "render.png"

    with sync_playwright() as p:
        try:
            # Launch local headless instance cleanly
            browser = p.chromium.launch(headless=True)

            # 🔒 Hardened Context Setup
            context = browser.new_context(
                viewport={"width": 1280, "height": 720},
                java_script_enabled=False,  # ❌ Paralyzes browser exploits and tracking pixels
                ignore_https_errors=True,  # Still extracts data if phishing page uses dead/expired SSL
                permissions=[]  # Completely strips microphone, webcam, and location access
            )

            page = context.new_page()

            # 4. 🕦 Real-Time Threat Capture
            # Strict 5-second timeout handles un-resolvable or infinite-loading "tarpit" sites
            response = page.goto(url, timeout=5000, wait_until="domcontentloaded")

            # Capture screenshot for safe preview isolation container
            page.screenshot(path=str(screenshot_path), timeout=3000)

            # Detect malicious URL redirects (Your original redirect idea made smart)
            if response and response.url != url:
                behavior_score += 25
                behavior_findings.append(f"Suspicious live redirect detected to: {response.url}")

            # Extract actual visible page text safely (Stripping raw HTML scripts)
            raw_inner_text = page.inner_text("body")
            page_text = raw_inner_text.lower() if raw_inner_text else ""

            # 5. 🔍 Live Behavioral Content Heuristics (Replacing the fake content simulations)
            harvesting_keywords = ["login", "password", "verify account", "sign in", "credential"]
            if any(keyword in page_text for keyword in harvesting_keywords):
                behavior_score += 25
                behavior_findings.append("Credential harvesting language found on landing page")

            urgency_keywords = ["urgently", "identity", "suspended", "action required", "hours left"]
            if any(keyword in page_text for keyword in urgency_keywords):
                behavior_score += 20
                behavior_findings.append("Urgent psychological manipulation found on landing page")

            brand_spoofs = ["microsoft", "paypal", "google", "apple", "bank", "netflix"]
            if any(brand in page_text for brand in brand_spoofs) and not any(brand in url for brand in brand_spoofs):
                behavior_score += 30
                behavior_findings.append(
                    "Brand impersonation detected (Brand named on page but absent from domain structure)")



        except Exception as e:

            error_str = str(e)

            # --- BEAUTIFUL TERMINAL ERROR RENDERING ---

            print("\n" + "=" * 60)

            print("🌐 NETWORK RESOLUTION FAILURE DETECTED")

            print("=" * 60)

            print(f"🔗 Target URL:  {url}")

            if "ERR_NAME_NOT_RESOLVED" in error_str:
                print("NON-EXISTENT DOMAIN (NXDOMAIN)")
                print("This domain is not registered or has no active DNS records.")
                behavior_score += 40  # Higher penalty for completely fake domains
                behavior_findings.append("Critical: Target domain does not exist in DNS ")
                page_text = "Analysis failed: The domain name does not exist in public DNS directories."

            else:

                print("🚨 Status:      CONNECTION TIMEOUT / DROPPED")
                print("💡 Insight:     The server took too long to respond or actively blocked the sandbox.")
                behavior_score += 15
                behavior_findings.append("Target site failed to respond (Network timeout or server unresponsive)")
                page_text = "Analysis failed: Network timeout while trying to fetch landing page."

            print("=" * 60 + "\n")

            # ------------------------------------------

            # Log the ugly technical error behind the scenes to your log file, keeping the terminal clean

            logger.debug(f"Technical Traceback: {error_str}")

    # 7. Final normalization (Your Original Rule)
    if behavior_score > 100:
        behavior_score = 100

    print(f"[SANDBOX] Final Score: {behavior_score}")

    # Preserves exact tuple expectation
    return behavior_score, behavior_findings, page_text
