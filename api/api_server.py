import uuid
import logging
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from playwright.async_api import async_playwright, Browser

# Setup isolated logger
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("phishield_api")

app = FastAPI(title="PhiShield API", version="2.0")


# --- Global Browser Pool State ---
class PlaywrightLifecycle:
    def __init__(self):
        self.browser: Browser = None
        self.playwright = None

    async def start(self):
        self.playwright = await async_playwright().start()
        # Launch master chromium process
        self.browser = await self.playwright.chromium.launch(headless=True)
        logger.info("[+] PhiShield Global Browser Sandbox Pool Initialized.")

    async def stop(self):
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()
        logger.info("[-] PhiShield Browser Sandbox Pool Terminated.")


pool = PlaywrightLifecycle()


@app.on_event("startup")
async def startup_event():
    await pool.start()


@app.on_event("shutdown")
async def shutdown_event():
    await pool.stop()


# Dependency injector to pass the secure browser into your pipeline
async def get_browser_pool() -> Browser:
    return pool.browser


# --- Models ---
class EmailRequest(BaseModel):
    raw_content: str
    user_id: str = "anonymous"


class ScanResponse(BaseModel):
    scan_id: str
    score: int
    verdict: str
    findings: list
    recommendation: str


# --- Endpoints ---
@app.get("/health")
async def health_check():
    return {"status": "online", "engine": "PhiShield-v2"}


@app.post("/scan", response_model=ScanResponse)
async def scan_email(request: EmailRequest, browser: Browser = Depends(get_browser_pool)):
    """
    Receives raw email string, processes parallel tasks asynchronously, and returns the verdict.
    """
    scan_id = str(uuid.uuid4())

    try:
        raw_bytes = request.raw_content.encode("utf-8")

        # 🛡️ Zero Consequence Fix: Import your pipeline as an async-compatible orchestration layer
        # You will pass the shared browser instance straight into your Playwright task
        from core.pipeline import run_pipeline_async

        result = await run_pipeline_async(raw_bytes, user=request.user_id, browser_pool=browser)

        return ScanResponse(
            scan_id=scan_id,
            score=result["score"],
            verdict=result["verdict"],
            findings=result["findings"],
            recommendation="Quarantine" if result["quarantine"] else "Allow"
        )

    except ValueError as val_err:
        # Catch bad formatting flaws without crashing the server thread
        logger.error(f"[!] Validation anomaly on scan {scan_id}: {str(val_err)}")
        raise HTTPException(status_code=422, detail="Invalid email payload format")

    except Exception as e:
        logger.critical(f"[-] Critical system bypass or flaw caught on scan {scan_id}: {str(e)}")
        # Secure Default Fail state: If code fails, quarantine the email by default
        return ScanResponse(
            scan_id=scan_id,
            score=100,
            verdict="SYSTEM_ERROR_FAIL_SECURE",
            findings=["Internal processing pipeline threw an unhandled exception."],
            recommendation="Quarantine"
        )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
