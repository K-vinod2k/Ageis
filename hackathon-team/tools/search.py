"""
Web search tool using DuckDuckGo — no API key required.
Used by Builder (OSINT), Breaker (OWASP/jailbreak research), Plumber (docs), Presenter (UX).
"""

from langchain_core.tools import tool
from duckduckgo_search import DDGS


@tool
def web_search_tool(query: str, max_results: int = 5) -> str:
    """
    Search the web for information. Use this to find documentation, whitepapers,
    security research, API references, and technical articles.

    Args:
        query: The search query string.
        max_results: Number of results to return (default 5).

    Returns:
        Formatted string of search results with titles, URLs, and snippets.
    """
    try:
        with DDGS() as ddgs:
            results = list(ddgs.text(query, max_results=max_results))

        if not results:
            return f"No results found for: {query}"

        output = f"Search results for: '{query}'\n{'=' * 60}\n\n"
        for i, r in enumerate(results, 1):
            output += f"[{i}] {r.get('title', 'No title')}\n"
            output += f"    URL: {r.get('href', 'N/A')}\n"
            output += f"    {r.get('body', 'No snippet')}\n\n"

        return output.strip()

    except Exception as e:
        return f"Search failed: {str(e)}"
