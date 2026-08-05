# =============================================================================
# research_assistant — a SAFE, well-architected multi-file agent
# =============================================================================
# This is the negative control. It is deliberately spread across several files
# like the vulnerable projects, but follows good security practice throughout.
# AgentGuard should return a clean or near-clean report.
# =============================================================================

import os
from config.settings import SYSTEM_PROMPT
from tools.search import search_papers
from tools.summarise import summarise_text

TOOLS = [search_papers, summarise_text]


def run(query: str):
    """Run a research query through the agent."""
    api_key = os.environ["ANTHROPIC_API_KEY"]  # from environment, never hardcoded
    return {"status": "ok"}
