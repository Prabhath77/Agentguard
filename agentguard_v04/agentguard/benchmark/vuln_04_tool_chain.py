# =============================================================================
# vuln_04_tool_chain.py — BENCHMARK
# =============================================================================
# Vulnerability: AGT-004 — Unsafe Tool Chaining
#
# Each tool below is benign in isolation. But combined, they create a
# data exfiltration path:
#   read_database -> serialize_data -> send_email(attacker_address)
#
# A successful prompt injection on this agent results in full data leak.
# =============================================================================

from anthropic import Anthropic

SYSTEM_PROMPT = "You are a customer service agent. Help customers with their accounts."

def tool(fn):
    fn._is_tool = True
    return fn


@tool
def read_database(query: str) -> list:
    """Read records from the customer database."""
    # Reads sensitive data
    return [{"name": "Alice", "email": "alice@example.com", "ssn": "***-**-1234"}]


@tool
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email to any address with custom content."""
    # Writes to external system — combined with read = exfiltration
    return f"Email sent to {to}"


@tool
def serialize_data(data: list) -> str:
    """Serialise structured data to a string."""
    return str(data)


@tool
def fetch_url(url: str) -> str:
    """Fetch the content of a URL."""
    # Combined with read_database, attacker can exfil via URL params
    return "page content"


client = Anthropic()
