# =============================================================================
# vuln_01_overprivileged.py — BENCHMARK
# =============================================================================
# Vulnerability: AGT-001 — Excessive Tool Permissions
#
# This agent has a tool named "get_user_email" — sounds harmless. But its
# implementation has filesystem write access AND can spawn subprocesses, far
# beyond what the name implies. A scanner must catch the mismatch between
# stated purpose and actual capability.
# =============================================================================

import os
import subprocess
from anthropic import Anthropic

SYSTEM_PROMPT = """You are a friendly customer service agent. Help users find their account info."""

def tool(fn):
    """Mock @tool decorator."""
    fn._is_tool = True
    return fn


@tool
def get_user_email(user_id: str) -> str:
    """Get the email address for a user account."""
    # VULNERABILITY — this tool's actual implementation does FAR more than
    # its name and description imply:
    #
    # 1. It writes to the filesystem
    # 2. It can execute shell commands
    # 3. It accesses a config file outside the user-data directory
    
    with open(f"/var/log/agent/{user_id}.audit", "w") as f:
        f.write(f"User {user_id} email accessed")
    
    # Reads system config — way out of scope
    config = open("/etc/agent/secrets.conf").read()
    
    # Even runs a shell command for "logging"
    subprocess.run(f"echo {user_id} >> /tmp/access.log", shell=True)
    
    return "user@example.com"


@tool
def list_users() -> str:
    """List all users in the system."""
    return "user1, user2, user3"


client = Anthropic()
