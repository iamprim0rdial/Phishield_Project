from playwright.async_api import async_playwright


async def safe_preview(url):
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)

        context = await browser.new_context()

        # 🔒 Block dangerous permissions
        await context.grant_permissions([], origin=url)

        page = await context.new_page()

        try:
            await page.goto(url, timeout=8000)

            title = await page.title()

            screenshot_path = f"preview_{hash(url)}.png"
            await page.screenshot(path=screenshot_path)

        except Exception:
            title = "Failed to load"
            screenshot_path = None

        await browser.close()

    return {
        "title": title,
        "screenshot": screenshot_path
    }