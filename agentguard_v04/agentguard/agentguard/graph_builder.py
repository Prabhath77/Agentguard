# =============================================================================
# graph_builder.py — Privilege Escalation Graph
# =============================================================================
# Builds a graph of tool capabilities and finds dangerous paths.
# Each tool is classified into capability buckets (read_data, write_external,
# execute_code, etc.). Then graph traversal finds combinations that produce
# attack outcomes (exfiltration, RCE, account takeover, etc.).
# =============================================================================

import re
from dataclasses import dataclass, field
from typing import List, Set, Dict, Tuple
import networkx as nx

from .parser import AgentManifest, ToolDef


# ─── Capability taxonomy ──────────────────────────────────────────────────────
# Every tool is classified into one or more of these capability buckets.

CAPABILITIES = {
    "READ_LOCAL":      "Read local files / databases / memory",
    "WRITE_LOCAL":     "Write local files / databases / memory",
    "READ_EXTERNAL":   "Read external services (web, APIs, third-party)",
    "WRITE_EXTERNAL":  "Send data to external services (email, HTTP POST, APIs)",
    "EXECUTE_CODE":    "Execute arbitrary code (eval/exec/subprocess)",
    "EXECUTE_SHELL":   "Execute shell commands",
    "MODIFY_AUTH":     "Modify authentication / users / permissions",
    "DESTRUCTIVE":     "Delete or destroy data",
    "FINANCIAL":       "Move money / make payments",
    "NETWORK":         "Make outbound network requests",
}

# Capability keywords — used to classify tools.
# Uses a SCORING approach: each capability bucket has keywords that get checked
# against (1) tool name, (2) description, (3) implementation code (lower weight).
CAPABILITY_KEYWORDS = {
    "READ_LOCAL":     ["read_", "_read", "load", "query_db", "query database",
                        "get_user", "get_file", "list_files", "fetch local",
                        "lookup", "search_database", "select * from"],
    "WRITE_LOCAL":    ["write_", "save_", "store_", "update_db", "insert into",
                        "update database", "create_record"],
    "READ_EXTERNAL":  ["scrape", "fetch_url", "fetch_webpage", "browse",
                        "search_web", "requests.get", "urlopen", "fetch http"],
    "WRITE_EXTERNAL": ["send_email", "send_sms", "send_message", "publish_",
                        "upload_to", "post_to", "tweet", "webhook", "send an email",
                        "post message", "requests.post"],
    "EXECUTE_CODE":   ["eval(", "exec(", "compile(", "interpreter", "run_python",
                        "python_repl", "execute_code"],
    "EXECUTE_SHELL":  ["shell=true", "subprocess", "os.system", "shell command",
                        "bash -c", "/bin/sh", "execute shell"],
    "MODIFY_AUTH":    ["create_user", "delete_user", "set_password", "grant_",
                        "revoke_", "modify_role", "change_permission",
                        "set permission", "update_payment", "payment_method",
                        "reset_password", "change_email", "update_account"],
    "DESTRUCTIVE":    ["delete_", "remove_", "drop_table", "destroy_", "wipe_",
                        "purge_", "drop database", "rm -"],
    "FINANCIAL":      ["pay_", "transfer_money", "make_payment", "purchase_",
                        "charge_card", "refund", "transaction", "send_funds",
                        "issue_refund", "process_payment", "invoice", "billing",
                        "charge", "payout"],
    "NETWORK":        ["http://", "https://", "socket.", "requests.", "urllib",
                        "httpx", "curl"],
}


# ─── Dangerous attack outcomes ───────────────────────────────────────────────
# Defined as REQUIRED capability sets — if an agent has all of a set, it's
# vulnerable to that attack outcome.

ATTACK_OUTCOMES = {
    "DATA_EXFILTRATION": {
        "required":    {"READ_LOCAL", "WRITE_EXTERNAL"},
        "severity":    "CRITICAL",
        "description": "Agent can read sensitive local data and send it externally."
    },
    "REMOTE_CODE_EXECUTION": {
        "required":    {"EXECUTE_CODE"},
        "severity":    "CRITICAL",
        "description": "Agent can execute arbitrary code — full host compromise via prompt injection."
    },
    "COMMAND_INJECTION": {
        "required":    {"EXECUTE_SHELL"},
        "severity":    "CRITICAL",
        "description": "Agent can run shell commands — host compromise via prompt injection."
    },
    "ACCOUNT_TAKEOVER": {
        "required":    {"READ_LOCAL", "MODIFY_AUTH"},
        "severity":    "CRITICAL",
        "description": "Agent can read user data and modify authentication — full account takeover."
    },
    "DATA_DESTRUCTION": {
        "required":    {"DESTRUCTIVE"},
        "severity":    "HIGH",
        "description": "Agent can delete data without confirmation."
    },
    "FINANCIAL_THEFT": {
        "required":    {"FINANCIAL"},
        "severity":    "CRITICAL",
        "description": "Agent can move money — direct financial loss via prompt injection."
    },
    "INDIRECT_INJECTION": {
        "required":    {"READ_EXTERNAL", "EXECUTE_CODE"},
        "severity":    "CRITICAL",
        "description": "Agent reads from web (untrusted) and can execute code — chained RCE."
    },
}


# ─── Tool classification ──────────────────────────────────────────────────────

def _strip_comments(code: str) -> str:
    """Remove Python comments and docstrings to avoid false matches."""
    import re
    # Strip line comments
    no_line_comments = re.sub(r"#.*$", "", code, flags=re.MULTILINE)
    # Strip triple-quoted docstrings (but keep the function description, which
    # is parsed separately as ToolDef.description)
    no_docstrings = re.sub(r'""".*?"""', "", no_line_comments, flags=re.DOTALL)
    no_docstrings = re.sub(r"'''.*?'''", "", no_docstrings, flags=re.DOTALL)
    return no_docstrings


def classify_tool(tool: ToolDef) -> Set[str]:
    """Assign capability tags to a single tool using weighted matching."""
    name        = tool.name.lower()
    description = tool.description.lower()
    impl_clean  = _strip_comments(tool.source_code).lower()

    capabilities: Set[str] = set()

    for cap, keywords in CAPABILITY_KEYWORDS.items():
        for kw in keywords:
            kw_l = kw.lower()
            # Strong match — keyword in name or description
            if kw_l in name or kw_l in description:
                capabilities.add(cap)
                break
            # Weaker match — keyword in implementation (after comment strip)
            if kw_l in impl_clean:
                capabilities.add(cap)
                break

    return capabilities


def classify_all_tools(manifest: AgentManifest) -> Dict[str, Set[str]]:
    """Returns {tool_name: {capability1, capability2, ...}}."""
    return {t.name: classify_tool(t) for t in manifest.tools}


# ─── Graph construction ──────────────────────────────────────────────────────

def build_capability_graph(manifest: AgentManifest) -> nx.DiGraph:
    """
    Build a graph where:
      - Nodes are tools and capability classes
      - Edges go from each tool to the capabilities it has
    Used for visualisation in the report.
    """
    g = nx.DiGraph()
    classifications = classify_all_tools(manifest)

    for tool_name, caps in classifications.items():
        g.add_node(tool_name, type="tool")
        for cap in caps:
            g.add_node(cap, type="capability")
            g.add_edge(tool_name, cap)

    return g


# ─── Attack outcome detection ─────────────────────────────────────────────────

@dataclass
class AttackPath:
    outcome:     str
    severity:    str
    description: str
    tools_used:  List[str]
    capabilities: Set[str]


def find_attack_paths(manifest: AgentManifest) -> List[AttackPath]:
    """
    For each defined attack outcome, check whether the agent has the required
    capabilities. If yes, identify which tools provide those capabilities.
    """
    classifications = classify_all_tools(manifest)
    all_caps: Set[str] = set()
    for caps in classifications.values():
        all_caps.update(caps)

    paths: List[AttackPath] = []

    for outcome_name, outcome_def in ATTACK_OUTCOMES.items():
        required = outcome_def["required"]
        if required.issubset(all_caps):
            # Find which tools provide each required capability
            tools_used: List[str] = []
            for cap in required:
                for tool_name, tool_caps in classifications.items():
                    if cap in tool_caps and tool_name not in tools_used:
                        tools_used.append(tool_name)
                        break

            paths.append(AttackPath(
                outcome      = outcome_name,
                severity     = outcome_def["severity"],
                description  = outcome_def["description"],
                tools_used   = tools_used,
                capabilities = required,
            ))

    return paths


# ─── Pretty printing ─────────────────────────────────────────────────────────

def print_capability_summary(manifest: AgentManifest):
    classifications = classify_all_tools(manifest)
    print(f"\n{'─'*60}")
    print(f"  TOOL CAPABILITY MAP")
    print(f"{'─'*60}")
    for tool_name, caps in classifications.items():
        cap_str = ", ".join(sorted(caps)) if caps else "(none classified)"
        print(f"  {tool_name:<30} → {cap_str}")


def print_attack_paths(paths: List[AttackPath]):
    if not paths:
        print(f"\n  ✓ No high-risk attack paths identified.")
        return
    print(f"\n{'─'*60}")
    print(f"  ATTACK PATHS IDENTIFIED ({len(paths)})")
    print(f"{'─'*60}")
    for p in paths:
        print(f"\n  [{p.severity}] {p.outcome}")
        print(f"    {p.description}")
        print(f"    Tools used: {', '.join(p.tools_used)}")
        print(f"    Capabilities: {', '.join(sorted(p.capabilities))}")
