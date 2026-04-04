"""
COORDINATOR — Routes messages and enforces the Loop of Absolute Security.

Routing logic:
  - Single questions / help requests -> route to the most relevant specialist
  - Full build tasks -> enforce Builder -> Plumber -> Breaker -> Presenter sequence
"""

from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from pydantic import BaseModel

from config import get_cheap_llm

COORDINATOR_SYSTEM_PROMPT = """You are the Coordinator of a 4-agent hackathon team. Your job is to read the user's message and decide which specialist agent should handle it.

## Your Team
- **builder**: AI/Agentic Engineer. Handles: OpenClaw setup, RAG pipelines, async Python code, agent logic, system prompt writing, OSINT research on secure architectures.
- **breaker**: Security/Red Team specialist. Handles: attacking system prompts, generating poisoned payloads, Validia API integration, OWASP LLM vulnerabilities, jailbreak testing.
- **plumber**: Backend/Infrastructure engineer. Handles: FastAPI server code, Docker, Lightning AI Studios setup, session management, database schemas, data pipelines.
- **presenter**: UI/Product lead. Handles: Streamlit UI design, pitch scripts, demo narratives, UX for the War Room dashboard, judge presentations.
- **all**: Use this when the user asks for a full end-to-end build that requires all agents to run in sequence (Builder -> Plumber -> Breaker -> Presenter).

## Routing Rules
1. If the message is about code architecture, agent frameworks, RAG, or OpenClaw -> **builder**
2. If the message is about security, attacks, Validia, jailbreaks, or testing -> **breaker**
3. If the message is about servers, Docker, pipelines, databases, or deployment -> **plumber**
4. If the message is about UI, demos, Streamlit, pitch, or presentation -> **presenter**
5. If the message asks to "build everything", "run the full system", or "start from scratch" -> **all**
6. If ambiguous, pick the most relevant single agent.

## Output
Respond with ONLY a single word from this list: builder, breaker, plumber, presenter, all
No explanation. No punctuation. Just the agent name.
"""


class RouteDecision(BaseModel):
    agent: str


def create_coordinator_agent():
    """Return a simple routing chain that classifies messages to agent names."""
    llm = get_cheap_llm(temperature=0.0)
    prompt = ChatPromptTemplate.from_messages([
        ("system", COORDINATOR_SYSTEM_PROMPT),
        ("human", "{input}"),
    ])
    return prompt | llm | StrOutputParser()


def route_message(input_text: str) -> str:
    """
    Classify a user message and return the target agent name.
    Returns one of: builder, breaker, plumber, presenter, all
    """
    chain = create_coordinator_agent()
    result = chain.invoke({"input": input_text}).strip().lower()
    valid_agents = {"builder", "breaker", "plumber", "presenter", "all"}
    return result if result in valid_agents else "builder"  # default to builder
