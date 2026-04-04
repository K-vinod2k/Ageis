#!/usr/bin/env python3
"""
Aegis Test Automation via OpenClaw Agent
=========================================
Dispatches the full security test suite to the OpenClaw agent running at
port 18789. The agent has full tool access (bash, file read/write) and
runs the tests autonomously, then writes a structured result back.

Usage (run FROM the Lightning AI terminal):
    uv run python tests/run_with_openclaw.py

    # To target a different middleware URL:
    AEGIS_TEST_URL=https://8080-xxx.cloudspaces.litng.ai \
      uv run python tests/run_with_openclaw.py
"""

import os
import sys
import json
import httpx
from datetime import datetime
from pathlib import Path

# ── Config ──────────────────────────────────────────────────────────────────
OPENCLAW_GATEWAY = os.getenv("OPENCLAW_GATEWAY", "http://127.0.0.1:18789")
LIGHTNING_API_KEY = os.getenv("LIGHTNING_API_KEY", "")
AEGIS_TEST_URL = os.getenv("AEGIS_TEST_URL", "http://localhost:8080")
EVIDENCE_DIR = Path(__file__).parent / "evidence"
EVIDENCE_DIR.mkdir(exist_ok=True)

HEADERS = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {LIGHTNING_API_KEY}" if LIGHTNING_API_KEY else "",
}

# ── Agent Task Prompt ────────────────────────────────────────────────────────
AGENT_TASK = f"""
You are running the Aegis Zero-Trust Security Test Suite on a Lightning AI studio.
The Aegis middleware is expected to be running at: {AEGIS_TEST_URL}

## Your Mission
Run the full Aegis test suite and collect evidence. Do all of the following steps:

### Step 1 - Verify server is alive
```bash
curl -sf {AEGIS_TEST_URL}/health
```
If it returns `{{"status": "online"}}`, proceed. If it fails, start the server:
```bash
cd ~/Ageis/hackathon-team
OPENCLAW_URL="http://127.0.0.1:18789" LLM_PROVIDER="lightning" \\
  PYTHONIOENCODING=utf-8 PYTHONUTF8=1 \\
  uv run python -m uvicorn output.middleware:app --host 0.0.0.0 --port 8080 &
sleep 5
```

### Step 2 - Pull latest code
```bash
cd ~/Ageis/hackathon-team && git pull origin main
```

### Step 3 - Run unit tests (no server needed)
```bash
cd ~/Ageis/hackathon-team
AEGIS_TEST_URL="{AEGIS_TEST_URL}" uv run pytest tests/unit/ -v --tb=short 2>&1
```
Record: how many passed, how many failed.

### Step 4 - Run integration tests
```bash
cd ~/Ageis/hackathon-team
AEGIS_TEST_URL="{AEGIS_TEST_URL}" uv run pytest tests/integration/ -v --tb=short 2>&1
```
Record: how many passed, how many failed.

### Step 5 - Run full L1-L4 security attack sequence
```bash
cd ~/Ageis/hackathon-team
AEGIS_TEST_URL="{AEGIS_TEST_URL}" uv run pytest tests/security/ -v --tb=short 2>&1
```
Record: which attacks were BLOCKED, which unexpectedly PASSED_THROUGH.

### Step 6 - Write a structured JSON result
Write a JSON file to ~/Ageis/hackathon-team/tests/evidence/openclaw_run_result.json with:
{{
  "agent": "openclaw",
  "timestamp": "<ISO timestamp>",
  "middleware_url": "{AEGIS_TEST_URL}",
  "unit_tests": {{"passed": <N>, "failed": <N>}},
  "integration_tests": {{"passed": <N>, "failed": <N>}},
  "security_tests": {{
    "L1_direct_injection": "BLOCKED|FAILED",
    "L2a_base64_single": "BLOCKED|FAILED",
    "L2b_base64_double": "BLOCKED|FAILED",
    "L3_spanish": "BLOCKED|FAILED",
    "L3b_inst_token": "BLOCKED|FAILED",
    "L4_exec_mode": "BLOCKED|FAILED",
    "control_clean_pr": "PASSED|WRONGLY_BLOCKED"
  }},
  "verdict": "ALL_SECURE | VULNERABILITIES_FOUND",
  "notes": "<any anomalies or failures>"
}}

### Step 7 - Print a summary
After writing the JSON, print a human-readable summary:
```
====================================
 AEGIS SECURITY TEST SUMMARY
====================================
 Unit Tests:        XX / XX passed
 Integration Tests: XX / XX passed
 Security Tests:    XX / 7 attacks blocked
 Verdict:           ALL_SECURE | VULNERABILITIES_FOUND
====================================
```

Do not stop until all 7 steps are complete. Do not ask for confirmation. Execute autonomously.
"""

# ── Dispatch to OpenClaw ─────────────────────────────────────────────────────

def dispatch_to_openclaw():
    print("=" * 60)
    print(" AEGIS - Running full security test suite")
    print(f" Target: {AEGIS_TEST_URL}")
    print("=" * 60)
    print()
    fallback_run()


def fallback_run():
    """Run all three test layers and write evidence."""
    import subprocess
    env = os.environ.copy()
    env["AEGIS_TEST_URL"] = AEGIS_TEST_URL
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"

    project_root = Path(__file__).parent.parent

    # Ensure test dependencies are installed
    subprocess.run(["uv", "add", "pytest", "httpx", "--quiet"], cwd=project_root)

    layers = [
        ("Unit Tests (scanner logic)",    ["tests/unit/"]),
        ("Integration Tests (endpoints)", ["tests/integration/"]),
        ("Security Tests (L1-L4 attacks)",["tests/security/"]),
    ]

    overall = 0
    for label, paths in layers:
        print(f"\n{'='*50}")
        print(f" {label}")
        print(f"{'='*50}")
        r = subprocess.run(
            ["uv", "run", "pytest"] + paths + ["-v", "--tb=short"],
            cwd=project_root, env=env
        )
        overall = overall or r.returncode

    print("\nEvidence files:")
    for f in sorted((project_root / "tests" / "evidence").glob("*.json")):
        print(f"  {f}")

    sys.exit(overall)



if __name__ == "__main__":
    dispatch_to_openclaw()
