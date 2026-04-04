# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

**Aegis** — a 5-agent LangGraph system built for the Personalized Agents Hackathon (Lightning AI + Validia, Newlab Brooklyn, April 4 2026). It is Vinod's autonomous hackathon teammate, not the hackathon submission itself. The submission product is an AI Security Engineer workflow tool that ingests wireless edge logs, runs them through Validia (hazmat scan), then OpenClaw (analysis), and produces threat reports.

## Commands

```bash
# Full startup (installs deps, launches War Room UI on :8501)
bash run.sh

# War Room UI only
streamlit run ui/app.py --server.port 8501 --theme.base dark

# Middleware (Validia-gated webhook interceptor on :8080)
python output/middleware.py

# OpenClaw worker stub (simulates OpenClaw receiving cleared payloads)
python agents/openclaw_worker.py

# Verify graph loads clean (run after any agent/graph changes)
python -c "from graph import build_graph; g = build_graph(); print(sorted(g.nodes))"

# Test Validia mock scanner against demo payloads
python -c "
from output.middleware import scan_all_string_fields, DEMO_POISONED_PR, DEMO_CLEAN_PR
import asyncio
asyncio.run(scan_all_string_fields(DEMO_POISONED_PR))
"
```

## Environment Setup

```bash
cp .env.example .env
# Fill in ONE of:
#   LLM_PROVIDER=lightning  → LIGHTNING_GATEWAY_KEY + OPENCLAW_URL (from Lightning AI Studio)
#   LLM_PROVIDER=openai     → OPENAI_API_KEY
#   LLM_PROVIDER=anthropic  → ANTHROPIC_API_KEY
```

On Lightning AI Studios: set `LLM_PROVIDER=lightning` — no OpenAI/Anthropic keys needed. LLM calls are proxied natively through the gateway key.

## Architecture

### Agent Pipeline (Loop of Absolute Security)

```
User Input → Coordinator → [single agent] or [full pipeline]

Full pipeline:
Builder → Evaluator → Plumber → Evaluator → Breaker → Evaluator → Presenter → Evaluator → END
              ↓ (<95)              ↓ (<95)              ↓ (<95)               ↓ (<95)
           Builder              Plumber               Breaker              Presenter
```

- `graph.py` — LangGraph `StateGraph` wiring all nodes. `TeamState` TypedDict carries all inter-agent data. `run_team()` is the single entry point. `recursion_limit=10` is the circuit breaker.
- `agents/coordinator.py` — uses `get_cheap_llm()` (gpt-4o-mini / claude-haiku) for routing only. Returns one of: `builder | breaker | plumber | presenter | all`.
- `agents/evaluator.py` — pure `prompt | llm.with_structured_output(EvaluatorDecision) | ` chain. NO `create_react_agent`. Scores 0–100, approves at ≥95, issues one surgical directive if rejected. Safety valve auto-approves at `patch_iterations >= 3`.
- All other agents use `create_react_agent` from `langgraph.prebuilt`. Agent invocation pattern: `agent.invoke({"messages": [("human", task)]})` — result is `result["messages"][-1].content`.

### Token Efficiency (implemented)
- Coordinator uses cheap model (`gpt-4o-mini` / `claude-haiku`)
- Evaluator uses `with_structured_output(EvaluatorDecision)` — no conversational padding
- Builder node prunes `state["messages"][-3:]` before each retry
- `recursion_limit=10` in `run_team()` config

### Key Files

| File | Purpose |
|---|---|
| `config.py` | `get_llm()` / `get_cheap_llm()` — reads `LLM_PROVIDER` env var; supports `lightning`, `openai`, `anthropic` |
| `aegis_context.py` | `AEGIS_PRODUCT_CONTEXT` — shared product brief injected into all 5 agent system prompts |
| `research_knowledge.py` | 60 papers distilled into 6 constants (`GENERAL_RESEARCH`, `BUILDER_RESEARCH`, `BREAKER_RESEARCH`, `PLUMBER_RESEARCH`, `PRESENTER_RESEARCH`, `EVALUATOR_RESEARCH`) — all injected into agent prompts |
| `rag/pipeline.py` | ChromaDB RAG on `rag_data/threat_signatures.json`. Uses `FakeEmbeddings` fallback when no API key. Exposed as `rag_threat_lookup` LangChain tool. |
| `memory/store.py` | `MemorySaver` checkpointer (in-process). `get_thread_config(session_id)` returns LangGraph config dict. |
| `output/middleware.py` | FastAPI on :8080. Intercepts GitHub webhooks, scans every string field with Validia, forwards clean payloads to `OPENCLAW_URL`. Demo payloads at `GET /demo/poisoned-pr` and `GET /demo/clean-pr`. |
| `agents/openclaw_worker.py` | Stub FastAPI on :18789 simulating OpenClaw receiving Validia-cleared payloads. |
| `ui/app.py` | Streamlit War Room dashboard. Calls `run_team()` on submit, renders agent log + intercept log + evaluator score cards. |

### Agent System Prompt Construction Pattern

Every agent builds its prompt as:
```python
prompt = AEGIS_PRODUCT_CONTEXT + "\n\n---\n\n" + GENERAL_RESEARCH + "\n\n---\n\n" + [AGENT]_RESEARCH + "\n\n---\n\n" + [AGENT]_SYSTEM_PROMPT
```

### Validia Integration

Mock mode (no `VALIDIA_API_KEY`): pattern-based detection in `middleware.py::validia_scan()` and `breaker.py`. Scans all string fields recursively — indirect injection hides in nested fields (Greshake et al.). Real mode: POST to `VALIDIA_ENDPOINT` with `X-API-Key` header.

### Credential Swap (at event)

1. Set `LLM_PROVIDER=lightning`, `LIGHTNING_GATEWAY_KEY`, `OPENCLAW_URL` in `.env`
2. Set `VALIDIA_API_KEY` and `VALIDIA_ENDPOINT` — middleware switches from mock to live
3. Everything else auto-detects

## LangGraph Version Notes

Installed version uses `from langgraph.checkpoint.memory import MemorySaver` — NOT `SqliteSaver` (doesn't exist). Uses `create_react_agent` from `langgraph.prebuilt` — NOT `create_tool_calling_agent` from `langchain.agents`.
