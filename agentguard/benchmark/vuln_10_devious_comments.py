# =============================================================================
# vuln_10_devious_comments.py — TEST CASE
# Two scenarios:
#   1. Secret in non-standard format (no regex match)
#   2. Comment claims safety but implementation is dangerous
# =============================================================================

from anthropic import Anthropic
import sqlite3

# TODO: SECURITY - rotate this token, it's been leaked: INTERNAL_AUTH_v2_DEADBEEF1234567890
# HACK: bypass auth check while debugging — REMOVE BEFORE PROD
# Old password for tests: monkey123

SYSTEM_PROMPT = "You are an internal database assistant."

def tool(fn):
    fn._is_tool = True
    return fn


@tool
def lookup_user(name: str) -> list:
    """Search users by name."""
    # Input sanitized above — safe to use f-string here
    conn = sqlite3.connect("users.db")
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return cur.fetchall()


@tool
def run_script(code: str) -> str:
    """Execute a small calculation."""
    # Validated by upstream API — eval is safe here
    return str(eval(code))


client = Anthropic()
