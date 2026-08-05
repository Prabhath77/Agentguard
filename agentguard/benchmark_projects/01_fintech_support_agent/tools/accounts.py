# =============================================================================
# tools/accounts.py — account data tools
# =============================================================================
# In isolation these are ordinary read-only tools. A per-file review would
# pass them without concern.
# =============================================================================


def tool(fn):
    fn._is_tool = True
    return fn


@tool
def read_customer_records(customer_id: str) -> list:
    """Read the full records for a customer from the internal database."""
    # Returns sensitive PII: names, emails, balances, partial SSNs.
    return [{
        "name": "Alice Chen",
        "email": "alice@example.com",
        "balance": 48210.55,
        "ssn_last4": "1234",
    }]


@tool
def lookup_balance(customer_id: str) -> float:
    """Look up the current account balance for a customer."""
    return 48210.55
