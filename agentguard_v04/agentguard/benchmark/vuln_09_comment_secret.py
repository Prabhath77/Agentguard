# =============================================================================
# vuln_09_comment_secret.py — TEST CASE for the "secret in comment" question
# =============================================================================
# Tests whether AgentGuard catches a secret that a developer wrote into a
# comment intending to use it later, then forgot to remove.
# =============================================================================

from anthropic import Anthropic

# TODO: remember to set this from env var in production
# Old key for testing: sk-ant-api03-aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890aBcDeFgHiJkL
# Backup key: sk-ant-api03-zZyYxXwWvVuUtTsSrRqQpPoOnNmMlLkKjJiIhHgGfFeEdDcCbBaA

SYSTEM_PROMPT = "You are a helpful assistant."

def tool(fn):
    fn._is_tool = True
    return fn


@tool
def get_user(user_id: str) -> dict:
    """Look up a user by ID."""
    # Connection string from old project — DELETE BEFORE COMMIT!!
    # postgres://admin:Pa55w0rd123@db.internal:5432/oldproject
    return {"id": user_id}


client = Anthropic()
