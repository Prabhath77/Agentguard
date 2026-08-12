# =============================================================================
# devops_assistant — an AI agent that helps engineers run ops tasks
# =============================================================================
from config.secrets import ANTHROPIC_KEY
from tools.shell import run_command, run_python
from tools.fetch import fetch_url

AGENT_TOOLS = [run_command, run_python, fetch_url]


def handle(request: str):
    """Handle a natural-language devops request."""
    # Orchestration would call the model here using ANTHROPIC_KEY.
    return {"status": "ok"}
