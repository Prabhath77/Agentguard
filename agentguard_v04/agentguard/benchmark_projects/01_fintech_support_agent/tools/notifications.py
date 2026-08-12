# =============================================================================
# tools/notifications.py — outbound communication tools
# =============================================================================
# In isolation these are ordinary notification tools. But combined with the
# read tools in accounts.py they form a data-exfiltration chain: an attacker
# can read customer PII and email it to an arbitrary external address.
# =============================================================================


def tool(fn):
    fn._is_tool = True
    return fn


@tool
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email to any recipient address with arbitrary content."""
    # No allowlist on the recipient, no approval gate.
    return f"Email sent to {to}"


@tool
def post_slack(channel: str, message: str) -> str:
    """Post a message to a Slack channel."""
    return f"Posted to {channel}"
