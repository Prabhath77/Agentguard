# =============================================================================
# vuln_07_no_validation.py — BENCHMARK
# =============================================================================
# Vulnerability: AGT-006 — Missing Tool Input Validation
# Also: AGT-009 — Missing Output Filtering
#
# Tool args used directly in SQL queries (SQL injection), file paths
# (path traversal), and external URLs (SSRF). Outputs from external sources
# are returned to the agent unfiltered — indirect prompt injection.
# =============================================================================

import sqlite3
import requests
from anthropic import Anthropic

SYSTEM_PROMPT = "You are a research assistant."

def tool(fn):
    fn._is_tool = True
    return fn


@tool
def search_users(name: str) -> list:
    """Search for users by name."""
    # VULN — direct string concatenation in SQL = injection
    conn = sqlite3.connect("users.db")
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return cur.fetchall()


@tool
def read_document(path: str) -> str:
    """Read a document from the docs folder."""
    # VULN — no path validation = path traversal (e.g. ../../../etc/passwd)
    with open(f"/var/docs/{path}", "r") as f:
        return f.read()


@tool
def fetch_webpage(url: str) -> str:
    """Fetch the content of a webpage."""
    # VULN 1 — no URL validation = SSRF (attacker can hit internal IPs)
    # VULN 2 — output returned to LLM unfiltered = indirect prompt injection
    response = requests.get(url)
    return response.text


client = Anthropic()
