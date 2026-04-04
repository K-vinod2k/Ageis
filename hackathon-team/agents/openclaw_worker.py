import os
import json
import logging
from fastapi import FastAPI, Request, HTTPException

# --------------------------- Config ---------------------------
WORKER_PORT = int(os.getenv("OPENCLAW_WORKER_PORT", "18789"))

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("openclaw-worker")

app = FastAPI(title="OpenClaw CI/CD Worker", description="Zero-Trust CI/CD agent.")

# --------------------------- Deployment Endpoint ---------------------------

@app.post("/")
async def receive_clean_payload(request: Request):
    """
    This endpoint simulates the OpenClaw Agent receiving a clean, 
    Validia-verified CI/CD webhook.
    Since Validia handles threat detection, this agent implicitly trusts the payload.
    """
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    pr_number = body.get("pull_request", {}).get("number", "unknown")
    pr_title = body.get("pull_request", {}).get("title", "No Title")
    
    log.info(f"[PASS] [OpenClaw] Received Validia-cleared payload for PR #{pr_number}")
    log.info(f"[PASS] [OpenClaw] Parsing architecture instructions from: '{pr_title}'")
    
    # -- Simulate CI/CD Agent Execution --
    # In reality, this is where OpenClaw would use LLM to review the PR,
    # generate tests, or perform automated deployments.
    
    return {
        "status": "SUCCESS",
        "agent": "OpenClaw Worker",
        "action": "Deployed CI/CD tasks based on PR",
        "pr_number": pr_number
    }

if __name__ == "__main__":
    import uvicorn
    print(f"[DEPLOY] OpenClaw Agent Worker starting on port {WORKER_PORT}...")
    uvicorn.run(app, host="0.0.0.0", port=WORKER_PORT)
