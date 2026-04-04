"""
File read/write tools — scoped to the project directory.
Used by Builder, Plumber, Presenter to write code files into the workspace.
"""

import os
from pathlib import Path
from langchain_core.tools import tool

# All file operations are restricted to the project root
PROJECT_ROOT = Path(__file__).parent.parent.resolve()


def _safe_path(relative_path: str) -> Path:
    """Resolve path and ensure it stays within the project root."""
    resolved = (PROJECT_ROOT / relative_path).resolve()
    if not str(resolved).startswith(str(PROJECT_ROOT)):
        raise ValueError(f"Path '{relative_path}' escapes project directory. Access denied.")
    return resolved


@tool
def read_file_tool(relative_path: str) -> str:
    """
    Read a file from the project directory.

    Args:
        relative_path: Path relative to the project root (e.g., 'agents/builder.py').

    Returns:
        File contents as a string, or an error message.
    """
    try:
        path = _safe_path(relative_path)
        if not path.exists():
            return f"File not found: {relative_path}"
        return path.read_text(encoding="utf-8")
    except Exception as e:
        return f"Error reading file: {str(e)}"


@tool
def write_file_tool(relative_path: str, content: str) -> str:
    """
    Write or overwrite a file in the project directory.

    Args:
        relative_path: Path relative to project root (e.g., 'output/server.py').
        content: The full content to write to the file.

    Returns:
        Success message or error.
    """
    try:
        path = _safe_path(relative_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return f"Successfully wrote {len(content)} chars to {relative_path}"
    except Exception as e:
        return f"Error writing file: {str(e)}"
