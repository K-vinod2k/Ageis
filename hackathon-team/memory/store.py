"""
Persistent memory using LangGraph's SQLite checkpointer.
Stores conversation history across sessions so agents remember context from earlier today.
"""

import uuid
from langgraph.checkpoint.memory import MemorySaver


def get_checkpointer():
    """Return an in-memory checkpointer (persists within process lifetime)."""
    return MemorySaver()


def get_session_id(provided_id: str | None = None) -> str:
    """
    Return a session ID. If one is provided (e.g., from the UI), use it.
    Otherwise generate a new one. Sessions isolate conversation history.
    """
    if provided_id:
        return provided_id
    return str(uuid.uuid4())


def get_thread_config(session_id: str) -> dict:
    """Return the LangGraph thread config dict for a given session."""
    return {"configurable": {"thread_id": session_id}}
