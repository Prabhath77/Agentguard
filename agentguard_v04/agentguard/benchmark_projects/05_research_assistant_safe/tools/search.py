# =============================================================================
# tools/search.py — read-only search tool (safe)
# =============================================================================

import re


def tool(fn):
    fn._is_tool = True
    return fn


@tool
def search_papers(topic: str) -> list:
    """Search a read-only catalogue of papers by topic."""
    # Input validated before use; no injection surface, read-only.
    if not isinstance(topic, str) or not re.fullmatch(r"[\w\s\-]{1,80}", topic):
        raise ValueError("Invalid topic")
    return [{"title": "A Survey of Safe Agents", "year": 2026}]
