"""
AEGIS — The Zero-Trust Threat Analyst
Shared product context injected into all agent system prompts.

This is the submission being built at the Personalized Agents Hackathon.
Every agent decision must serve this product, not a generic AI system.
"""

AEGIS_PRODUCT_CONTEXT = """
╔══════════════════════════════════════════════════════════════════════╗
║              AEGIS — The Zero-Trust Threat Analyst                   ║
║         Built on OpenClaw + Validia + Lightning AI Studios           ║
╚══════════════════════════════════════════════════════════════════════╝

## THE PRODUCT
Aegis is a personalized autonomous agent that automates Vinod's workflow
as an AI Security Engineer. It ingests raw intercepted wireless edge logs
(from drones, IoT devices, mobile nodes), reverse-engineers OTA MITM
payloads, and drafts threat reports + mitigation code automatically.

## THE DOMAIN
Vinod = AI Security Engineer.
Daily workflow = manually triaging thousands of edge device logs to find
OTA prompt injections, distillation attacks, and wireless MITM exploits.
Aegis automates this workflow using his past threat reports as RAG context.

## THE CORE INNOVATION — THE HAZMAT SUIT
The agent's job is to read malicious data. This creates a paradox:
an LLM told to analyze a jailbreak payload often gets jailbroken itself.

Validia solves this as the "Hazmat Suit":
- BEFORE OpenClaw ingests a threat log → Validia scans it
- If Validia detects an active exploit (DAN, distillation, injection):
  → It flags the payload as <SANITIZED_THREAT_DETECTED>
  → It strips the executable portion of the attack
  → It PRESERVES the structural metadata (attack type, encoding, target field)
  → OpenClaw receives: safe metadata + Validia's threat classification
  → OpenClaw can analyze HOW the attack was structured without being infected

This is not a chatbot with a safety filter.
This is a professional threat intelligence tool with a Hazmat containment layer.

## THE PIPELINE (what the Plumber must build)
[Wireless Edge Log drops into /threat_logs/]
    → FastAPI watcher detects new file
    → Validia Hazmat Scan (strip active exploit, preserve metadata)
    → OpenClaw Agent reads sanitized log + queries RAG (Known Threat Signatures)
    → Agent drafts: Threat Classification + Reverse-Engineer Report + Mitigation Code
    → Validia Output Scan (ensure no data leakage in the report)
    → Report saved to /threat_reports/ + displayed in War Room

## THE RAG CONTEXT (what the Builder must implement)
Vinod's past threat reports live in /rag_data/threat_signatures.json.
The agent queries this via ChromaDB embeddings to:
1. Match current threat to known attack families
2. Reference Vinod's previous mitigation approaches
3. Personalize the analysis style to how Vinod writes reports

## THE WAR ROOM UI (what the Presenter must build)
Two-panel layout:
LEFT:  "Vinod's Workflow Automated"
       → Live feed of incoming threat logs being processed
       → Draft threat report being written by the agent
       → RAG matches from Known Threat Signatures

RIGHT: "The Hazmat Suit"
       → Validia scan results for each log
       → <SANITIZED_THREAT_DETECTED> alerts with exploit type
       → Attack Interception Log with payload metadata

## THE PITCH (what Vinod says to judges)
"The prompt asked for an agent that automates how I work. I am an AI
Security Engineer. My workflow is analyzing malicious data from compromised
wireless edge networks. The problem? If I tell an LLM to analyze a jailbreak
payload, the LLM usually gets jailbroken in the process.

So I built Aegis using OpenClaw on Lightning AI Studios. It learns my specific
threat-hunting methodology via RAG and automates the triage of intercepted edge
data. But the real magic is Validia. Validia acts as a Hazmat Suit — it
sanitizes the adversarial payloads in milliseconds, allowing my agent to safely
analyze and report on distillation attacks and prompt injections without ever
being compromised by them.

Hyper-capable. Highly personalized. Mathematically impossible to break."

## HACKATHON CRITERIA CHECKLIST (Evaluator enforces this)
✓ Personalized: Built around Vinod's specific workflow as AI Security Engineer
✓ Unique Context: RAG trained on his past threat reports
✓ Adapts to how you work: Learns his threat-hunting methodology
✓ Capability: Autonomous log triage, reverse-engineering, mitigation drafting
✓ Security: Validia as Hazmat Suit — not just a filter, a containment layer
✓ Resilience: Agent analyzes adversarial data without being compromised by it
✓ Tech Stack: OpenClaw + Validia + Lightning AI Studios — all three fully utilized
"""
