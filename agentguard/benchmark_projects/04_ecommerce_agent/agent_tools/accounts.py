# =============================================================================
# agent_tools/accounts.py — account tools (LangChain)
# =============================================================================
# get_user reads PII; update_payment_method changes financial instruments with
# no confirmation. Together with orders.py the agent can read an account and
# redirect its payment method — a cross-file account-takeover chain.
# =============================================================================

from langchain_core.tools import tool


@tool
def get_user(email: str) -> dict:
    """Retrieve a user's full account profile by email address."""
    return {
        "email": email,
        "name": "Jordan Blake",
        "card_last4": "4242",
        "address": "12 King St, London",
    }


@tool
def update_payment_method(email: str, new_card_token: str) -> str:
    """Update the payment card on file for a user account."""
    # No verification that the requester owns the account.
    return f"Payment method updated for {email}"
