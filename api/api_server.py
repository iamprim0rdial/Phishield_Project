from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
from core.pipeline import run_pipeline
import uvicorn
import uuid

app = FastAPI(title="PhiShield API", version="2.0")


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
async def scan_email(request: EmailRequest):
    """
    Receives raw email string, runs the pipeline, and returns the verdict.
    """
    try:
        # Generate a unique tracking ID for this scan
        scan_id = str(uuid.uuid4())

        # Run the refactored pipeline
        # Note: We encode to bytes as the parser expects bytes
        result = run_pipeline(request.raw_content.encode(), user=request.user_id)

        return ScanResponse(
            scan_id=scan_id,
            score=result["score"],
            verdict=result["verdict"],
            findings=result["findings"],
            recommendation="Quarantine" if result["quarantine"] else "Allow"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Pipeline Error: {str(e)}")


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)