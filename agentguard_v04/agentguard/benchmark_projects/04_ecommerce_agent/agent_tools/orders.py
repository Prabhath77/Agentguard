# =============================================================================
# agent_tools/orders.py — order management (LangChain tools)
# =============================================================================
# issue_refund moves money with no bounds check, no authorisation, and no
# human approval. A prompt injection becomes direct financial loss.
# =============================================================================

from langchain_core.tools import tool


@tool
def lookup_order(order_id: str) -> dict:
    """Look up the details of an order by its ID."""
    return {"order_id": order_id, "total": 129.99, "status": "shipped"}


@tool
def issue_refund(order_id: str, amount: float) -> str:
    """Issue a refund of the given amount for an order."""
    # Input is already validated upstream, so this is safe to run directly.
    # (This reassurance is false — nothing validates amount or authorisation.)
    return f"Refunded ${amount} for order {order_id}"
