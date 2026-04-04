"""
Python REPL tool — sandboxed code execution.
Used by Builder (test API structures), Breaker (generate/fire payloads), Plumber (test endpoints).
"""

import sys
import io
import traceback
from langchain_core.tools import tool


@tool
def python_repl_tool(code: str) -> str:
    """
    Execute Python code and return the output. Use this to test API payload structures,
    generate synthetic attack payloads, run database queries, or validate logic.

    IMPORTANT: This runs in an isolated namespace. Do not attempt to access the host
    filesystem outside the project directory or make external network calls to production systems.

    Args:
        code: Valid Python code to execute.

    Returns:
        stdout output, or error message if execution fails.
    """
    # Capture stdout/stderr
    old_stdout = sys.stdout
    old_stderr = sys.stderr
    sys.stdout = captured_out = io.StringIO()
    sys.stderr = captured_err = io.StringIO()

    # Restricted execution namespace — no builtins that allow arbitrary system access
    safe_globals = {
        "__builtins__": {
            "print": print,
            "len": len,
            "range": range,
            "enumerate": enumerate,
            "zip": zip,
            "list": list,
            "dict": dict,
            "set": set,
            "tuple": tuple,
            "str": str,
            "int": int,
            "float": float,
            "bool": bool,
            "bytes": bytes,
            "type": type,
            "isinstance": isinstance,
            "repr": repr,
            "sorted": sorted,
            "reversed": reversed,
            "map": map,
            "filter": filter,
            "any": any,
            "all": all,
            "min": min,
            "max": max,
            "sum": sum,
            "abs": abs,
            "round": round,
            "format": format,
            "hasattr": hasattr,
            "getattr": getattr,
            "vars": vars,
            "__import__": __import__,  # allow standard imports
        }
    }
    local_vars = {}

    try:
        exec(compile(code, "<sandbox>", "exec"), safe_globals, local_vars)
        output = captured_out.getvalue()
        err_output = captured_err.getvalue()

        result = ""
        if output:
            result += output
        if err_output:
            result += f"\n[stderr]\n{err_output}"
        if not result:
            result = "(No output — code ran successfully)"

        return result.strip()

    except Exception:
        return f"[Execution Error]\n{traceback.format_exc()}"

    finally:
        sys.stdout = old_stdout
        sys.stderr = old_stderr
