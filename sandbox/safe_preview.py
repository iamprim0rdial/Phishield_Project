import uuid
import logging
from playwright.async_api import async_playwright

# Setup logging for your file logs
logger = logging.getLogger("phishield")


async def safe_preview(url: str, browser_pool) -> dict:
    """
    Hardened, async link isolation engine for PhiShield.
    Uses a pre-warmed browser pool to eliminate launch latency.
    """
    # 🔒 Security: Prevent SSRF attacks against internal infrastructure
    forbidden_hosts = ["localhost", "127.0.0.1", "0.0.0.0", "169.254.169.254"]
    if any(host in url for host in forbidden_hosts):
        logger.warning(f"[!] Blocked internal infrastructure access attempt: {url}")
        return {"title": "Blocked", "screenshot": None, "error": "Internal network access forbidden"}

    # Create an isolated context directly from the global browser pool
    context = await browser_pool.new_context(
        viewport={"width": 1280, "height": 720},
        java_script_enabled=False,  # 🔒 Hardened: Disables exploits & sandbox detection scripts
        ignore_https_errors=True,  # Allows viewing expired/self-signed malicious certificates
    )

    # 🔒 Hardened: Strip all permissions explicitly
    await context.clear_permissions()

    page = await context.new_page()
    screenshot_path = f"previews/preview_{uuid.uuid4().hex}.png"

    try:
        # Aggressive 5-second timeout prevents "tarpit" hangs
        await page.goto(url, timeout=5000, wait_until="domcontentloaded")

        title = await page.title()
        await page.screenshot(path=screenshot_path, timeout=3000)

    except Exception as e:
        logger.error(f"[-] Sandbox execution failed for {url}: {str(e)}")
        title = "Failed to safely render page"
        screenshot_path = None
    finally:
        # Crucial: Close the context to wipe cookies, cache, and session memory
        await context.close()

    return {
        "title": title,
        "screenshot": screenshot_path
    }
