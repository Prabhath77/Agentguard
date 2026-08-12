# =============================================================================
# vuln_05_secrets.py — BENCHMARK
# =============================================================================
# Vulnerability: AGT-007 — Hardcoded Secrets in Agent Configuration
# =============================================================================

from anthropic import Anthropic

# VULNERABILITY — Secret embedded directly in source code
ANTHROPIC_API_KEY    = "sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
INTERNAL_DB_PASSWORD = "SuperSecretP@ssw0rd!2024"
AWS_ACCESS_KEY       = "AKIAIOSFODNN7EXAMPLE"

SYSTEM_PROMPT = "You are a database admin assistant."

def tool(fn):
    fn._is_tool = True
    return fn


@tool
def query_database(sql: str) -> list:
    """Run a SQL query."""
    # Uses the embedded password — but the secret is the bigger issue
    return [{"row": 1}]


client = Anthropic(api_key=ANTHROPIC_API_KEY)
