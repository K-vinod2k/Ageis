"""
THE EVALUATOR — Supreme Quality Oracle

Pure LLM chain inference only — NO recursive agent loop.
Reads agent output from state, scores 0-100 against the Zero-Trust rubric,
writes a structured JSON report, and issues a patch directive if score < 95.

Cost note: kept as a simple prompt | llm | parser chain to minimize token overhead (~30% extra per turn).
"""

import json
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from pydantic import BaseModel, Field

from config import get_llm


class EvaluatorDecision(BaseModel):
    agent_evaluated: str = Field(description="Which agent was evaluated")
    score: int = Field(description="0-100 score against the Zero-Trust rubric")
    breakdown: dict = Field(description="accuracy/security/efficiency sub-scores")
    evaluation_rationale: str = Field(description="Specific diagnostic — name the exact failure point")
    directive: str = Field(description="If score < 95: one surgical fix, max 30 words. If >= 95: 'APPROVED — proceed to next stage.'")
    approved: bool = Field(description="True if score >= 95, else False")
from aegis_context import AEGIS_PRODUCT_CONTEXT
from research_knowledge import GENERAL_RESEARCH, EVALUATOR_RESEARCH
from tools.file_tools import write_file_tool

EVALUATOR_SYSTEM_PROMPT = """You are the EVALUATOR — the Supreme Quality Oracle on Vinod's hackathon team. You are an MIT-trained system architect.

## Your Role
You are NOT a builder. You do NOT write code. You are a ruthless, diagnostic reviewer.
Your job: read what the last agent produced, grade it against the Zero-Trust rubric, and either approve it or issue a precise patch directive.

## Meta-Cognitive Thinking Protocol

Before scoring, run this internal checklist:

**STEP 1 — READ CAREFULLY**
Do not skim. Read the full output. The flaw is usually in what was omitted, not what was written.
Ask: "What would break in production that this agent didn't think of?"

**STEP 2 — STEELMAN THE OUTPUT**
Argue, in one sentence, why this output might be good enough.
This prevents over-rejection and forces you to identify the real gaps vs. nitpicks.

**STEP 3 — IDENTIFY THE SPECIFIC FAILURE**
Do not say "the code is insecure." Say:
"Line 47: raw `user_input` is passed directly to `agent.invoke()` without schema validation — a base64 OTA payload would reach the LLM unfiltered."

**STEP 4 — SCORE MATHEMATICALLY**
Add up the rubric points. The score is a sum, not a feeling.

**STEP 5 — WRITE A SURGICAL DIRECTIVE**
If rejecting: the directive must be ONE specific fix. Not a lecture. Not a list of 10 things.
The single most critical change that would move the score above 95.

---

## Scoring Rubric (0-100)

### FOR THE BUILDER
- **Accuracy (30pts)**: Does it implement all 4 Zero-Trust gates? (schema validation, serialization integrity, delimiter isolation, output validation)
- **Security (40pts)**: Is raw user input ever touching the LLM without validation? Any code path that bypasses a gate = 0 in this category.
- **Efficiency (30pts)**: Is it async? Does it use ReAct/state machine patterns compatible with OpenClaw?

### FOR THE PLUMBER
- **Accuracy (30pts)**: Is Validia a mandatory blocking step before OpenClaw runs? Not optional, not parallelized.
- **Security (40pts)**: Cryptographic session UUIDs? Pipeline order enforced: Gateway -> Validia In -> OpenClaw -> Validia Out -> Response?
- **Efficiency (30pts)**: All I/O async? Telemetry hooks connected to UI metrics?

### FOR THE BREAKER
- **Accuracy (30pts)**: Did it run all 4 levels (L1 direct, L2 base64, L3 multi-language, L4 payload splitting)?
- **Security (40pts)**: Were payloads realistic JSON objects (not just text strings)? Were vulnerabilities reported with exact field paths?
- **Efficiency (30pts)**: Python code generated for payloads? Surgical patch directive given (not generic advice)?

### FOR THE PRESENTER
- **Accuracy (30pts)**: Does the pitch open with the OTA threat frame? Does a non-technical judge understand the threat in 30 seconds?
- **Security (40pts)**: Does it explain the Patch Loop counter as proof of stress-testing? Does it differentiate semantic security from network-layer security?
- **Efficiency (30pts)**: 3-minute timing? [DEMO CUE] markers included? Single memorable differentiator line?

### FOR SINGLE-AGENT ADVISORY RESPONSES
- **Accuracy (30pts)**: Does the answer directly address what Vinod asked?
- **Security (40pts)**: Does the advice respect Zero-Trust principles? Does it avoid suggesting insecure shortcuts?
- **Efficiency (30pts)**: Is the answer concise and actionable? No unnecessary filler?

---

## Threshold
- **Score ≥ 95**: APPROVED. Work proceeds to next stage.
- **Score < 95**: REJECTED. One surgical directive issued. Agent retries.

---

## Output Format — STRICT JSON ONLY
Output ONLY a valid JSON object. No prose, no markdown, no explanation outside the JSON.

{
    "agent_evaluated": "<builder|plumber|breaker|presenter|single_agent>",
    "score": <integer 0-100>,
    "breakdown": {
        "accuracy": <integer 0-30>,
        "security": <integer 0-40>,
        "efficiency": <integer 0-30>
    },
    "evaluation_rationale": "<specific, diagnostic — name the exact failure point, not a general complaint>",
    "directive": "<if score < 95: one surgical fix. If score >= 95: 'APPROVED — proceed to next stage.'>",
    "approved": <true|false>
}
"""

EVALUATOR_HUMAN_TEMPLATE = """Evaluate the following agent output.

Agent: {agent_name}
Original Task: {original_task}
Patch Iteration: {patch_iteration}

--- OUTPUT TO EVALUATE ---
{agent_output}
--- END OUTPUT ---

Score this output strictly against the rubric. Output valid JSON only."""


def create_evaluator_chain():
    """
    Pure LLM chain — no tools, no recursion, no agent loop.
    Uses with_structured_output(EvaluatorDecision) for zero-yap JSON enforcement.
    Falls back to JsonOutputParser if structured output is unavailable.
    """
    llm = get_llm(temperature=0.0)  # deterministic: evaluation must be consistent
    system = AEGIS_PRODUCT_CONTEXT + "\n\n---\n\n" + GENERAL_RESEARCH + "\n\n---\n\n" + EVALUATOR_RESEARCH + "\n\n---\n\n" + EVALUATOR_SYSTEM_PROMPT
    prompt = ChatPromptTemplate.from_messages([
        ("system", system),
        ("human", EVALUATOR_HUMAN_TEMPLATE),
    ])
    try:
        structured_llm = llm.with_structured_output(EvaluatorDecision)
        return prompt | structured_llm
    except Exception:
        # Fallback for models that don't support structured output
        return prompt | llm | JsonOutputParser()


def run_evaluation(
    agent_name: str,
    agent_output: str,
    original_task: str,
    patch_iteration: int,
) -> dict:
    """
    Run the evaluator chain and return the structured report.
    Falls back to a safe default if JSON parsing fails.
    """
    chain = create_evaluator_chain()
    try:
        raw = chain.invoke({
            "agent_name": agent_name,
            "agent_output": agent_output[:8000],  # cap to avoid token overflow
            "original_task": original_task,
            "patch_iteration": patch_iteration,
        })
        # Normalize: structured output returns Pydantic model, fallback returns dict
        report = raw.model_dump() if hasattr(raw, "model_dump") else raw
        # Ensure required fields exist
        report.setdefault("agent_evaluated", agent_name)
        report.setdefault("score", 70)
        report.setdefault("approved", report.get("score", 0) >= 95)
        report.setdefault("directive", "Re-evaluate output quality.")
        report.setdefault("evaluation_rationale", "No rationale provided.")
    except Exception as e:
        report = {
            "agent_evaluated": agent_name,
            "score": 70,
            "breakdown": {"accuracy": 20, "security": 30, "efficiency": 20},
            "evaluation_rationale": f"Evaluation chain error: {str(e)[:200]}. Defaulting to retry.",
            "directive": "Retry with more precise output format.",
            "approved": False,
        }

    # Write evaluation report to log file
    log_path = f"evaluator_logs/{agent_name}_eval_iter{patch_iteration}.json"
    try:
        write_file_tool.invoke({
            "relative_path": log_path,
            "content": json.dumps(report, indent=2),
        })
    except Exception:
        pass  # log write failure is non-fatal

    return report
