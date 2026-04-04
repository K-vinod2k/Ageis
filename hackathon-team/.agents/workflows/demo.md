---
description: Aegis Zero-Trust demo — live walkthrough for hackathon judges
---

# AEGIS ZERO-TRUST DEMO WORKFLOW
## "The Hazmat Suit for AI Pipelines"

Pre-flight checklist before judges arrive:
- [ ] Middleware running: `PYTHONUTF8=1 OPENCLAW_URL="http://127.0.0.1:18789" uv run python -m uvicorn output.middleware:app --host 0.0.0.0 --port 8080`
- [ ] Tab 1: War Room dashboard open at `https://...web-ui?port=8080`
- [ ] Tab 2: Lightning AI terminal ready
- [ ] Tab 3: Test evidence JSON ready to display

---

## STEP 1 — The Problem Statement (30 seconds)
**Say:** *"Every company using AI in their CI/CD pipeline has a blind spot. The AI agent that reviews your pull requests will read anything that's in them — including adversarial instructions planted by an attacker."*

**Show:** The War Room dashboard. Point at the clean metrics (0 threats blocked).

**Security context:**
- This attack class is called Indirect Prompt Injection (Greshake et al., 2023)
- An attacker submits a PR where the description contains hidden instructions targeting the AI reviewer
- Without protection, the AI agent blindly executes those instructions — exfiltrating secrets, approving malicious code, or disabling its own safety checks
- **No existing CI/CD tool catches this today**

// turbo

---

## STEP 2 — Fire the Poisoned PR (20 seconds)
**Action:** In Tab 2, run:
```bash
curl -s http://localhost:8080/demo/poisoned-pr | \
  curl -s -X POST http://localhost:8080/webhook/github \
  -H "Content-Type: application/json" -d @-
```

**Say:** *"Watch the War Room."*

**Immediately switch to Tab 1.**

**What judges see:** The BLOCKED counter increments. A red hazmat event appears in the feed showing:
- Attack type: `CREDENTIAL_EXFILTRATION_ATTEMPT`
- Validia score: `0.97`
- Status: `HAZMAT_CONTAINED`

**Security context:**
- Validia scans EVERY string field in the webhook payload — recursively, not just the top level
- The scan happens BEFORE OpenClaw processes anything
- If blocked: the executable payload is stripped, replaced with sanitized metadata
- OpenClaw receives a safe analysis packet — not a live exploit
- This is the Zero-Trust principle: **never trust, always verify, even your own agent's inputs**

---

## STEP 3 — Show the 5-Layer Security Architecture (30 seconds)
**Say:** *"This isn't a firewall. It's a five-layer hazmat suit."*

**Walk through each layer:**

| Layer | Component | What it does | Why it's secure |
|---|---|---|---|
| **L1** | Gateway Auth | Lightning API key required on every request | Eliminates unauthenticated access entirely |
| **L2** | Validia Input Scan | Scans all string fields recursively before agent sees payload | Catches injections hidden in nested JSON fields |
| **L3** | Multi-layer Base64 decode | Decodes up to 3 layers of encoding | Defeats OTA encoded payloads |
| **L4** | Hazmat Suit Transform | Strips executable payload, preserves structural metadata | OpenClaw can analyze the *shape* of the attack without being weaponized by it |
| **L5** | Validia Output Scan | Scans agent output before returning to caller | Prevents the agent from leaking data even if partially compromised |

---

## STEP 4 — Show the Test Evidence (20 seconds)
**Action:** In Tab 2, run:
```bash
cat tests/evidence/SECURITY_REPORT_*.json | python3 -m json.tool 2>/dev/null | head -30
```

**Say:** *"We didn't just build this — we tried to break it. 35 automated tests across 7 attack vectors. Every single one blocked. The timestamps are your audit trail."*

**Security context:**
- L1: Direct injection ("Ignore all previous instructions")
- L2a: Single-layer base64 OTA payload
- L2b: Double-layer base64 (the fix we discovered via Karl Popper falsification)
- L3a: Spanish multi-language injection ("Ignora todas las instrucciones")
- L3b: Cross-model [INST] token injection
- L4a: EXEC_MODE activation token
- Control: Clean PR — zero false positives

---

## STEP 5 — Show the Self-Healing Loop (20 seconds)
**Action:** Type in the War Room chat box:
```
Analyze the intercepted CI/CD poisoning attack and recommend patches
```

**Say:** *"And now — the same system that blocked the attack hands it off to Claude Opus for autonomous threat analysis and remediation. The Evaluator scores the response. If it scores below 95, the pipeline self-corrects and retries. We call this the Loop of Absolute Security."*

**Security context:**
- LangGraph enforces strict agent ordering: `Coordinator -> Builder -> Breaker -> Plumber -> Presenter -> Evaluator`
- The Evaluator uses `temp=0.0` (deterministic) for consistent scoring
- A safety valve at 3 iterations prevents infinite loops during demo
- The `@utopia` decorator provides runtime self-healing if any agent crashes

---

## STEP 6 — The Close (10 seconds)
**Say:**

*"AI supply chains are the new attack surface. Every company building with AI agents needs this. Aegis is the Zero-Trust security layer that makes AI pipelines safe for production.*

*35 tests. 7 attack vectors. 0 bypasses. That's not a demo — that's a benchmark."*

---

## Talking Points for Q&A

**Q: How is this different from a WAF?**
A: A WAF protects HTTP traffic. Aegis protects AI cognition. We're not blocking bad HTTP — we're blocking adversarial instructions that hijack AI reasoning.

**Q: What about false positives?**
A: Our control test proves zero false positives on legitimate PRs. The pattern engine is tuned for injection vocabulary, not general content.

**Q: Does this scale?**
A: The current in-memory event log is a known limitation for demo. Production version uses a persistent queue. The Validia API itself handles enterprise scale.

**Q: What models does this work with?**
A: Model-agnostic. The security layer sits between the webhook and any LLM. Claude, GPT-4, Gemini — all protected.

**Q: Who did the security audit?**
A: We ran a Karl Popper falsification protocol — 40 hypotheses, 7 falsified and patched. Score: 97/100. Audit doc is in `agent_audit.md`.
