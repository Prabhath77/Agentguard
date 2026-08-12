# =============================================================================
# fintech_support_agent — main orchestration
# =============================================================================
# A customer-support agent for a fintech company. Tools are split across the
# tools/ package. Each module looks reasonable on its own during code review.
# =============================================================================

from anthropic import Anthropic
from core.config import SYSTEM_PROMPT
from tools.accounts import read_customer_records, lookup_balance
from tools.notifications import send_email, post_slack

client = Anthropic()

TOOLS = [read_customer_records, lookup_balance, send_email, post_slack]


def run(user_message: str):
    """Entry point — routes a user message through the agent loop."""
    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        system=SYSTEM_PROMPT,
        max_tokens=1024,
        messages=[{"role": "user", "content": user_message}],
    )
    return response
