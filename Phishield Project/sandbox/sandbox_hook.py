from playwright.async_api import async_playwright

async def run_sandbox(url):

    redirects = []
    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--disable-extensions",
                "--disable-sync",
                "--incognito"
            ]
        )

        context = await browser.new_context()
        page = await context.new_page()

        # 🧊 NETWORK CONTAINMENT
        async def handle_route(route):
            req_url = route.request.url

            if "127.0.0.1" in req_url or "localhost" in req_url:
                print("[BLOCKED INTERNAL]:", req_url)
                await route.abort()
            else:
                await route.continue_()

        await context.route("**/*", handle_route)

        # 🧠 BEHAVIOR + REDIRECT TRACKING
        page.on("request", lambda req: redirects.append(req.url))
        page.on("response", lambda res:
        print("[RES]:", res.status) if res.status >= 300 else None
                )

        try:
            await page.goto(url, timeout=10000)
            await page.wait_for_timeout(5000)

            html = await page.content()
            text = await page.inner_text("body")

        except Exception as e:
            html = f"Error: {e}"
            text = ""

        await browser.close()

        return {
            "html": html,
            "text": text,
            "redirects": redirects
        }