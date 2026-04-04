"""
LLM factory — reads LLM_PROVIDER env var and returns the right chat model.
Supports OpenAI and Anthropic. Swap to OpenClaw tomorrow by replacing get_llm().
"""

import os
from dotenv import load_dotenv

load_dotenv()

LLM_PROVIDER = os.getenv("LLM_PROVIDER", "openai").lower()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
OPENCLAW_API_KEY = os.getenv("OPENCLAW_API_KEY", "")
VALIDIA_API_KEY = os.getenv("VALIDIA_API_KEY", "")
LIGHTNING_GATEWAY_KEY = os.getenv("LIGHTNING_GATEWAY_KEY", "")
OPENCLAW_URL = os.getenv("OPENCLAW_URL", "")
LIGHTNING_API_KEY = os.getenv("LIGHTNING_API_KEY", "")
MEMORY_DB_PATH = os.getenv("MEMORY_DB_PATH", "./memory/sessions.db")


def get_llm(temperature: float = 0.2):
    """Return the high-capability LLM. Used for Builder, Breaker, Plumber, Presenter, Evaluator."""
    if LLM_PROVIDER == "lightning":
        # Lightning AI proxies LLM calls natively — no OpenAI/Anthropic keys needed
        if not LIGHTNING_GATEWAY_KEY and not OPENCLAW_URL:
            raise ValueError("Set LIGHTNING_GATEWAY_KEY + OPENCLAW_URL in .env for Lightning AI mode")
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(
            model="gpt-4o",
            api_key=LIGHTNING_GATEWAY_KEY,
            base_url=f"{OPENCLAW_URL}/v1" if OPENCLAW_URL else None,
            temperature=temperature,
        )
    elif LLM_PROVIDER == "anthropic":
        if not ANTHROPIC_API_KEY:
            raise ValueError("ANTHROPIC_API_KEY not set in .env")
        from langchain_anthropic import ChatAnthropic
        return ChatAnthropic(
            model="claude-opus-4-6",
            api_key=ANTHROPIC_API_KEY,
            temperature=temperature,
        )
    else:  # default: openai
        if not OPENAI_API_KEY:
            raise ValueError("OPENAI_API_KEY not set in .env")
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(
            model="gpt-4o",
            api_key=OPENAI_API_KEY,
            temperature=temperature,
        )


def get_cheap_llm(temperature: float = 0.0):
    """Return a fast, cheap LLM. Used only for Coordinator routing — classification, not reasoning."""
    if LLM_PROVIDER == "lightning":
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(
            model="gpt-4o-mini",
            api_key=LIGHTNING_GATEWAY_KEY,
            base_url=f"{OPENCLAW_URL}/v1" if OPENCLAW_URL else None,
            temperature=temperature,
        )
    elif LLM_PROVIDER == "anthropic":
        if not ANTHROPIC_API_KEY:
            raise ValueError("ANTHROPIC_API_KEY not set in .env")
        from langchain_anthropic import ChatAnthropic
        return ChatAnthropic(
            model="claude-haiku-4-5-20251001",  # fastest/cheapest Anthropic model
            api_key=ANTHROPIC_API_KEY,
            temperature=temperature,
        )
    else:  # default: openai
        if not OPENAI_API_KEY:
            raise ValueError("OPENAI_API_KEY not set in .env")
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(
            model="gpt-4o-mini",  # ~10x cheaper than gpt-4o, 100ms routing latency
            api_key=OPENAI_API_KEY,
            temperature=temperature,
        )
