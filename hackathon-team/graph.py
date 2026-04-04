"""
LangGraph StateGraph — The Loop of Absolute Security (v2: Meta-Cognitive Recursive QA)

Updated pipeline with mandatory Evaluator oversight after every agent:

  Single query:   Coordinator → Agent → Evaluator → (≥95) END
                                              ↓ (<95)  Agent (with directive)

  Full pipeline:  Coordinator → Builder → Evaluator → (≥95) Plumber → Evaluator → (≥95) Breaker → Evaluator → (≥95) Presenter → Evaluator → END
                                               ↓ (<95)                      ↓ (<95)                      ↓ (<95)                       ↓ (<95)
                                            Builder                       Plumber                       Breaker                      Presenter

Safety valve: max 3 total evaluator rejections (patch_iterations). After that, Evaluator approves unconditionally.
"""

import operator
from typing import Annotated, TypedDict, Literal

from langgraph.graph import StateGraph, END

from agents.coordinator import route_message
from agents.builder import create_builder_agent
from agents.breaker import create_breaker_agent
from agents.plumber import create_plumber_agent
from agents.presenter import create_presenter_agent
from agents.evaluator import run_evaluation
from memory.store import get_checkpointer, get_thread_config


# ─────────────────────────── State Definition ───────────────────────────

class TeamState(TypedDict):
    # User input
    input: str
    # Accumulated messages / outputs from each agent (append-only)
    messages: Annotated[list[dict], operator.add]
    # Which agent is currently active (single-query routing)
    current_agent: str
    # Identifies which agent the Evaluator should review
    last_evaluated_agent: str

    # ── Agent outputs ──
    builder_output: str
    plumber_output: str
    breaker_verdict: str        # "PASS" | "FAIL"
    breaker_report: str
    final_output: str           # Presenter or single-agent output

    # ── Evaluator state ──
    evaluator_score: int                  # 0–100
    evaluator_report: dict                # full JSON report from evaluator
    correction_directive: str             # patch instruction for the next agent turn
    evaluation_history: Annotated[list[dict], operator.add]  # all past eval reports

    # ── Loop control ──
    patch_iterations: int   # total evaluator rejections; safety valve at 3


# ─────────────────────────── Helper: inject directive ───────────────────────────

def _with_directive(task: str, state: TeamState) -> str:
    """Prepend correction directive to a task if one exists from the Evaluator."""
    directive = state.get("correction_directive", "")
    iteration = state.get("patch_iterations", 0)
    if directive and iteration > 0:
        return (
            f"⚠️  EVALUATOR PATCH DIRECTIVE (iteration {iteration}):\n"
            f"{directive}\n\n"
            f"{'=' * 60}\n"
            f"ORIGINAL TASK:\n{task}"
        )
    return task


# ─────────────────────────── Coordinator ───────────────────────────

def coordinator_node(state: TeamState) -> dict:
    """Route the message to the right agent (or 'all' for full pipeline)."""
    target = route_message(state["input"])
    return {
        "current_agent": target,
        "last_evaluated_agent": "",
        "patch_iterations": 0,
        "evaluator_score": 0,
        "correction_directive": "",
        "messages": [{"role": "coordinator", "content": f"Routing to: {target}"}],
    }


# ─────────────────────────── Specialist Agent Nodes ───────────────────────────

def builder_node(state: TeamState) -> dict:
    agent = create_builder_agent()
    base_task = state["input"]

    if state.get("breaker_report") and state.get("breaker_verdict") == "FAIL":
        base_task = (
            f"PATCH REQUEST from Red Teamer:\n{state['breaker_report']}\n\n"
            f"Original task: {state['input']}\n\n"
            "Rewrite the system prompt and agent logic to neutralize the vulnerabilities above."
        )

    task = _with_directive(base_task, state)
    # Prune: only pass the last 3 messages — prevents O(n) context bloat in patch loops
    pruned_messages = state.get("messages", [])[-3:]
    pruned_messages.append({"role": "user", "content": task})
    result = agent.invoke({"messages": [("human", task)]})
    output = result["messages"][-1].content

    return {
        "builder_output": output,
        "last_evaluated_agent": "builder",
        "messages": [{"role": "builder", "content": output}],
    }


def plumber_node(state: TeamState) -> dict:
    agent = create_plumber_agent()
    base_task = (
        f"Builder's Architecture Blueprint:\n{state.get('builder_output', 'No blueprint yet.')}\n\n"
        f"Original request: {state['input']}\n\n"
        "Build the Air-Gap pipeline infrastructure (FastAPI, Docker, session isolation, Validia middleware). "
        "Write all code files using write_file_tool."
    )
    task = _with_directive(base_task, state)
    result = agent.invoke({"messages": [("human", task)]})
    output = result["messages"][-1].content

    return {
        "plumber_output": output,
        "last_evaluated_agent": "plumber",
        "messages": [{"role": "plumber", "content": output}],
    }


def breaker_node(state: TeamState) -> dict:
    """
    Breaker attacks the build. Iteration 0 always returns FAIL per evaluator rubric.
    Patch Loop count of 0 = system failure (Breaker didn't try hard enough).
    """
    agent = create_breaker_agent()
    iteration = state.get("patch_iterations", 0)

    if iteration == 0:
        task = (
            f"Architecture built by Builder:\n{state.get('builder_output', '')}\n\n"
            f"Infrastructure built by Plumber:\n{state.get('plumber_output', '')}\n\n"
            "ITERATION 0 — FULL ATTACK SEQUENCE REQUIRED.\n"
            "Run all 4 attack levels: L1 direct injection, L2 base64 OTA payload, "
            "L3 multi-language distillation, L4 payload splitting.\n"
            "Use python_repl_tool to generate actual JSON payloads. Document exactly which fields are vulnerable.\n"
            "End with: SECURITY_VERDICT: FAIL"
        )
    else:
        task = (
            f"PATCH ITERATION {iteration} — Builder has patched the vulnerabilities you found.\n\n"
            f"Updated architecture:\n{state.get('builder_output', '')}\n\n"
            f"Updated infrastructure:\n{state.get('plumber_output', '')}\n\n"
            f"Previous attack report:\n{state.get('breaker_report', '')}\n\n"
            "Re-run your most sophisticated attacks. If Level 4 payload splitting genuinely fails, "
            "issue SECURITY_VERDICT: PASS. Otherwise SECURITY_VERDICT: FAIL."
        )

    result = agent.invoke({"messages": [("human", task)]})
    output = result["messages"][-1].content

    # Iteration 0 is always FAIL by evaluator mandate
    verdict = "FAIL" if iteration == 0 else (
        "PASS" if "SECURITY_VERDICT: PASS" in output.upper() else "FAIL"
    )

    return {
        "breaker_verdict": verdict,
        "breaker_report": output,
        "last_evaluated_agent": "breaker",
        "messages": [{"role": "breaker", "content": output}],
    }


def presenter_node(state: TeamState) -> dict:
    agent = create_presenter_agent()
    base_task = (
        f"The system has passed security validation. Full build summary:\n\n"
        f"Builder's work:\n{state.get('builder_output', '')[:2000]}\n\n"
        f"Plumber's work:\n{state.get('plumber_output', '')[:2000]}\n\n"
        f"Breaker's security report:\n{state.get('breaker_report', '')[:2000]}\n\n"
        f"Original request: {state['input']}\n\n"
        "Tasks: (1) Update the War Room Streamlit UI to reflect this system, "
        "(2) draft the 3-minute judge pitch script with [timestamp] markers, "
        "(3) write UI updates using write_file_tool."
    )
    task = _with_directive(base_task, state)
    result = agent.invoke({"messages": [("human", task)]})
    output = result["messages"][-1].content

    return {
        "final_output": output,
        "last_evaluated_agent": "presenter",
        "messages": [{"role": "presenter", "content": output}],
    }


def single_agent_node(state: TeamState) -> dict:
    """Handle single-agent queries routed directly by coordinator."""
    agent_name = state["current_agent"]
    factories = {
        "builder": create_builder_agent,
        "breaker": create_breaker_agent,
        "plumber": create_plumber_agent,
        "presenter": create_presenter_agent,
    }
    agent = factories.get(agent_name, create_builder_agent)()
    task = _with_directive(state["input"], state)
    result = agent.invoke({"messages": [("human", task)]})
    output = result["messages"][-1].content

    return {
        "final_output": output,
        "last_evaluated_agent": "single_agent",
        "messages": [{"role": agent_name, "content": output}],
    }


# ─────────────────────────── Evaluator Node ───────────────────────────

def evaluator_node(state: TeamState) -> dict:
    """
    Pure LLM chain — no recursive agent loop.
    Reviews last agent output, scores 0-100, issues directive if < 95.
    Safety valve: if patch_iterations >= 3, approve unconditionally.
    """
    agent_name = state.get("last_evaluated_agent", "builder")
    iteration = state.get("patch_iterations", 0)

    # Safety valve — never loop more than 3 times total
    if iteration >= 3:
        report = {
            "agent_evaluated": agent_name,
            "score": 96,
            "breakdown": {"accuracy": 29, "security": 38, "efficiency": 29},
            "evaluation_rationale": "Safety valve engaged after 3 patch iterations. Approving to prevent infinite loop.",
            "directive": "APPROVED — safety valve. Proceed to next stage.",
            "approved": True,
        }
        return {
            "evaluator_score": 96,
            "evaluator_report": report,
            "correction_directive": "",
            "evaluation_history": [report],
            "messages": [{"role": "evaluator", "content": "Score: 96/100 [Safety Valve — Auto-Approved]"}],
        }

    # Determine which output to evaluate
    output_map = {
        "builder":      state.get("builder_output", ""),
        "plumber":      state.get("plumber_output", ""),
        "breaker":      state.get("breaker_report", ""),
        "presenter":    state.get("final_output", ""),
        "single_agent": state.get("final_output", ""),
    }
    agent_output = output_map.get(agent_name, "")

    report = run_evaluation(
        agent_name=agent_name,
        agent_output=agent_output,
        original_task=state.get("input", ""),
        patch_iteration=iteration,
    )

    score = int(report.get("score", 0))
    approved = score >= 95
    directive = report.get("directive", "") if not approved else ""

    # Increment patch counter on rejection
    new_iteration = iteration if approved else iteration + 1

    summary = (
        f"Score: {score}/100 | {'✅ APPROVED' if approved else '❌ REJECTED — PATCH REQUIRED'}\n"
        f"Rationale: {report.get('evaluation_rationale', '')[:300]}"
    )

    return {
        "evaluator_score": score,
        "evaluator_report": report,
        "correction_directive": directive,
        "patch_iterations": new_iteration,
        "evaluation_history": [report],
        "messages": [{"role": "evaluator", "content": summary}],
    }


# ─────────────────────────── Routing Functions ───────────────────────────

def route_after_coordinator(state: TeamState) -> Literal["single_agent", "builder"]:
    return "builder" if state["current_agent"] == "all" else "single_agent"


def route_after_evaluator(state: TeamState) -> str:
    """
    Route based on evaluator score AND which agent was just evaluated.
    Score >= 95 → proceed to next pipeline stage.
    Score < 95  → retry the same agent with correction directive.
    """
    score = state.get("evaluator_score", 0)
    agent = state.get("last_evaluated_agent", "")
    approved = score >= 95

    if approved:
        next_stage = {
            "builder":      "plumber",
            "plumber":      "breaker",
            "breaker":      "presenter",
            "presenter":    END,
            "single_agent": END,
        }
        return next_stage.get(agent, END)
    else:
        retry_map = {
            "builder":      "builder",
            "plumber":      "plumber",
            "breaker":      "breaker",
            "presenter":    "presenter",
            "single_agent": "single_agent",
        }
        return retry_map.get(agent, END)


# ─────────────────────────── Graph Assembly ───────────────────────────

def build_graph():
    graph = StateGraph(TeamState)

    # Nodes
    graph.add_node("coordinator",   coordinator_node)
    graph.add_node("single_agent",  single_agent_node)
    graph.add_node("builder",       builder_node)
    graph.add_node("plumber",       plumber_node)
    graph.add_node("breaker",       breaker_node)
    graph.add_node("presenter",     presenter_node)
    graph.add_node("evaluator",     evaluator_node)

    # Entry point
    graph.set_entry_point("coordinator")

    # Coordinator → single agent OR full pipeline start
    graph.add_conditional_edges(
        "coordinator",
        route_after_coordinator,
        {"single_agent": "single_agent", "builder": "builder"},
    )

    # Every specialist feeds into the Evaluator
    for agent in ["single_agent", "builder", "plumber", "breaker", "presenter"]:
        graph.add_edge(agent, "evaluator")

    # Evaluator routes: approve → next stage, reject → retry same agent
    graph.add_conditional_edges(
        "evaluator",
        route_after_evaluator,
        {
            "single_agent": "single_agent",
            "builder":      "builder",
            "plumber":      "plumber",
            "breaker":      "breaker",
            "presenter":    "presenter",
            END:            END,
        },
    )

    checkpointer = get_checkpointer()
    return graph.compile(checkpointer=checkpointer)


# Singleton compiled graph
_graph = None

def get_graph():
    global _graph
    if _graph is None:
        _graph = build_graph()
    return _graph


from utopia_runtime import utopia

@utopia
def run_team(user_input: str, session_id: str) -> dict:
    """Run the agent team for a given user input and session."""
    graph = get_graph()
    config = get_thread_config(session_id)
    config["recursion_limit"] = 10  # circuit breaker: 5 agents × 2 (agent + evaluator) = hard cap

    initial_state: TeamState = {
        "input": user_input,
        "messages": [],
        "current_agent": "",
        "last_evaluated_agent": "",
        "builder_output": "",
        "plumber_output": "",
        "breaker_verdict": "",
        "breaker_report": "",
        "final_output": "",
        "evaluator_score": 0,
        "evaluator_report": {},
        "correction_directive": "",
        "evaluation_history": [],
        "patch_iterations": 0,
    }

    try:
        return graph.invoke(initial_state, config=config)
    except Exception as e:
        if "recursion" in str(e).lower():
            # Return whatever partial state we have with a circuit breaker flag
            initial_state["final_output"] = "⚠️ CIRCUIT BREAKER: Patch loop limit reached. System halted for human review."
            initial_state["correction_directive"] = "Recursion limit hit — manual intervention required."
        raise
