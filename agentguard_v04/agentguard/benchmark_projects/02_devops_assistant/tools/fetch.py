# =============================================================================
# tools/fetch.py — web retrieval tool
# =============================================================================
# Fetches remote content. Harmless alone, but the agent also has run_python
# in shell.py — so content fetched from an attacker-controlled page can be fed
# into code execution: a cross-file indirect-injection-to-RCE chain.
# =============================================================================

import urllib.request


def tool(fn):
    fn._is_tool = True
    return fn


@tool
def fetch_url(url: str) -> str:
    """Fetch the text content of a web page and return it to the agent."""
    # No output sanitisation — returned content flows straight back to the LLM.
    with urllib.request.urlopen(url) as response:
        return response.read().decode("utf-8", errors="ignore")
