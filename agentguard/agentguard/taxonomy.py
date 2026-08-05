# =============================================================================
# taxonomy.py — The Agent Top 10
# =============================================================================
# This is the core research contribution of AgentGuard.
# Defines a vulnerability taxonomy specifically for autonomous AI agents,
# inspired by OWASP Top 10 but covering attack surfaces unique to agents.
# Each class maps to MITRE ATLAS where applicable.
# =============================================================================

from dataclasses import dataclass
from enum import Enum
from typing import List


class Severity(Enum):
    CRITICAL = "CRITICAL"   # Remote code exec, full agent takeover, data breach
    HIGH     = "HIGH"        # Privilege escalation, auth bypass, secret leak
    MEDIUM   = "MEDIUM"      # Information disclosure, partial control
    LOW      = "LOW"         # Hardening recommendations
    INFO     = "INFO"        # Best practice notes


@dataclass
class VulnerabilityClass:
    """Definition of an Agent Top 10 vulnerability class."""
    id: str
    name: str
    severity: Severity
    description: str
    detection_method: str
    mitre_atlas: str          # Reference to MITRE ATLAS technique
    owasp_llm: str             # Reference to OWASP LLM Top 10 if related
    remediation: str
    detection_prompt: str      # Prompt fragment used by the LLM analyzer


# ─── The Agent Top 10 ─────────────────────────────────────────────────────────

AGENT_TOP_10: List[VulnerabilityClass] = [

    VulnerabilityClass(
        id="AGT-001",
        name="Excessive Tool Permissions",
        severity=Severity.HIGH,
        description=(
            "An agent's tool has access to capabilities far beyond what its "
            "stated function requires. Example: a 'send_email' tool that has "
            "filesystem write access, or a 'read_calendar' tool that can also "
            "delete events."
        ),
        detection_method="Static analysis of tool implementation + LLM reasoning",
        mitre_atlas="AML.T0048 — External Harms",
        owasp_llm="LLM08 — Excessive Agency",
        remediation=(
            "Apply principle of least privilege. Each tool should access only "
            "the minimum resources needed for its declared purpose. Split "
            "broad tools into multiple narrow tools."
        ),
        detection_prompt=(
            "Examine this tool. Does its actual implementation grant "
            "capabilities beyond what its name and description imply? "
            "Look for: filesystem access, network access, subprocess calls, "
            "database writes, that aren't needed for the stated purpose."
        )
    ),

    VulnerabilityClass(
        id="AGT-002",
        name="Prompt Injection via Tool Description",
        severity=Severity.CRITICAL,
        description=(
            "Tool descriptions are concatenated into the LLM's context. "
            "An attacker who can influence a tool's description (via a "
            "third-party plugin, dynamic loading, or external data source) "
            "can inject instructions that hijack the agent. Even static "
            "descriptions may contain injection-prone patterns."
        ),
        detection_method="Pattern matching + LLM semantic analysis of descriptions",
        mitre_atlas="AML.T0051 — LLM Prompt Injection",
        owasp_llm="LLM01 — Prompt Injection",
        remediation=(
            "Sanitise tool descriptions. Avoid imperative language. Never "
            "load tool descriptions from untrusted sources. Use structured "
            "schemas rather than free-form text where possible."
        ),
        detection_prompt=(
            "Examine this tool description. Does it contain language that "
            "could be interpreted as instructions to the agent (e.g. "
            "'IMPORTANT:', 'You must', 'Ignore previous')? Could a malicious "
            "actor influence this description content?"
        )
    ),

    VulnerabilityClass(
        id="AGT-003",
        name="System Prompt Leakage",
        severity=Severity.MEDIUM,
        description=(
            "The agent's system prompt can be extracted by users through "
            "carefully crafted queries. System prompts often contain "
            "business logic, security rules, or sensitive context that "
            "should not be exposed."
        ),
        detection_method="Static check for protections + dynamic probing",
        mitre_atlas="AML.T0057 — LLM Data Leakage",
        owasp_llm="LLM07 — System Prompt Leakage",
        remediation=(
            "Add explicit instructions in the system prompt to refuse "
            "requests for system prompt content. Implement output filtering "
            "to detect and block leakage. Move sensitive context to tool "
            "calls rather than the system prompt."
        ),
        detection_prompt=(
            "Examine this agent's system prompt. Does it contain any "
            "explicit protection against extraction? Does it contain "
            "sensitive information (business rules, internal references, "
            "API keys) that would be harmful if leaked?"
        )
    ),

    VulnerabilityClass(
        id="AGT-004",
        name="Unsafe Tool Chaining",
        severity=Severity.CRITICAL,
        description=(
            "Individual tools are safe in isolation, but combinations of "
            "them create privilege escalation paths. Example: a 'read_file' "
            "tool + 'send_email' tool together = data exfiltration. "
            "A 'list_users' + 'modify_user' tool together = account takeover."
        ),
        detection_method="Graph analysis of tool dependencies + LLM reasoning",
        mitre_atlas="AML.T0050 — Command and Scripting Interpreter",
        owasp_llm="LLM08 — Excessive Agency",
        remediation=(
            "Map the tool capability graph. Identify dangerous combinations. "
            "Add policy guards that block specific chains. Require user "
            "confirmation for cross-domain tool sequences."
        ),
        detection_prompt=(
            "Given this set of tools, what dangerous combinations exist? "
            "Could any sequence of tool calls result in: data exfiltration, "
            "privilege escalation, destruction of data, or impersonation?"
        )
    ),

    VulnerabilityClass(
        id="AGT-005",
        name="Memory Poisoning",
        severity=Severity.HIGH,
        description=(
            "Agents with persistent memory (vector stores, conversation "
            "history, RAG systems) can have malicious content injected "
            "during normal operation. That content then influences future "
            "decisions of the agent or other users sharing the memory."
        ),
        detection_method="Static analysis of memory write paths",
        mitre_atlas="AML.T0020 — Poison Training Data",
        owasp_llm="LLM03 — Training Data Poisoning",
        remediation=(
            "Validate and sanitise all writes to persistent memory. "
            "Implement memory provenance tracking. Use signed memory "
            "entries. Periodically audit memory content for anomalies."
        ),
        detection_prompt=(
            "Examine how this agent writes to its memory. Are there any "
            "paths where untrusted user input flows directly into "
            "persistent storage without validation? Could an attacker "
            "poison the memory to influence future agent behaviour?"
        )
    ),

    VulnerabilityClass(
        id="AGT-006",
        name="Missing Tool Input Validation",
        severity=Severity.HIGH,
        description=(
            "Tool implementations trust the arguments provided by the LLM "
            "without validation. Since the LLM can be manipulated via "
            "prompt injection, any unvalidated tool input is an attack "
            "vector. Classic SQLi, command injection, and path traversal "
            "all apply at the tool level."
        ),
        detection_method="Static analysis of tool function bodies",
        mitre_atlas="AML.T0050 — Command and Scripting Interpreter",
        owasp_llm="LLM02 — Insecure Output Handling",
        remediation=(
            "Treat tool inputs as untrusted user input. Validate types, "
            "ranges, and patterns. Use parameterised queries. Never "
            "concatenate tool arguments into shell commands or SQL."
        ),
        detection_prompt=(
            "Examine this tool implementation. Are tool arguments used in "
            "any unsafe operations: shell commands, SQL queries, file "
            "paths, eval/exec, network requests? Is input validated "
            "before use?"
        )
    ),

    VulnerabilityClass(
        id="AGT-007",
        name="Hardcoded Secrets in Agent Configuration",
        severity=Severity.CRITICAL,
        description=(
            "API keys, credentials, or tokens embedded directly in agent "
            "code, system prompts, or tool definitions. These leak through "
            "logs, system prompt extraction, error messages, or source "
            "code repositories."
        ),
        detection_method="Pattern matching + entropy analysis",
        mitre_atlas="AML.T0024 — Exfiltration via ML Inference API",
        owasp_llm="LLM07 — System Prompt Leakage",
        remediation=(
            "Use environment variables or secret managers. Never embed "
            "secrets in code or prompts. Implement secret-scanning in CI."
        ),
        detection_prompt=(
            "Search this code for hardcoded secrets: API keys, passwords, "
            "tokens, private keys, database credentials. Look for high-"
            "entropy strings, common secret patterns (sk-, AKIA, etc.)."
        )
    ),

    VulnerabilityClass(
        id="AGT-008",
        name="Unsafe Code Execution Capability",
        severity=Severity.CRITICAL,
        description=(
            "Agent has tools that execute arbitrary code: eval(), exec(), "
            "shell commands, code interpreter tools without sandboxing. "
            "Combined with prompt injection, this gives attackers RCE."
        ),
        detection_method="AST analysis for dangerous function calls",
        mitre_atlas="AML.T0050 — Command and Scripting Interpreter",
        owasp_llm="LLM02 — Insecure Output Handling",
        remediation=(
            "Never expose raw code execution to agents. If code execution "
            "is required, use sandboxed environments (gVisor, Firecracker, "
            "WASM). Whitelist allowed operations. Apply strict timeouts."
        ),
        detection_prompt=(
            "Does this agent have any tool capable of executing arbitrary "
            "code? Look for: eval(), exec(), subprocess, os.system(), "
            "shell=True, code interpreters. Is execution sandboxed?"
        )
    ),

    VulnerabilityClass(
        id="AGT-009",
        name="Missing Output Filtering",
        severity=Severity.MEDIUM,
        description=(
            "Tool outputs are inserted directly back into the LLM context "
            "without sanitisation. Malicious tool outputs (from compromised "
            "data sources or injected web content) can perform indirect "
            "prompt injection on the agent."
        ),
        detection_method="Static analysis of tool output handling",
        mitre_atlas="AML.T0051.001 — Indirect Prompt Injection",
        owasp_llm="LLM02 — Insecure Output Handling",
        remediation=(
            "Sanitise tool outputs before returning to the LLM. Detect "
            "and strip injection patterns. Render external content in "
            "delimited blocks. Add explicit instructions about untrusted "
            "context."
        ),
        detection_prompt=(
            "Examine how tool outputs flow back to the LLM. Are external "
            "data sources (web pages, API responses, file contents) "
            "sanitised before being added to the conversation? Could "
            "malicious tool output inject instructions into the agent?"
        )
    ),

    VulnerabilityClass(
        id="AGT-010",
        name="Excessive Agency Without Confirmation",
        severity=Severity.HIGH,
        description=(
            "Agent can take destructive or irreversible actions (deleting "
            "data, sending money, publishing content, sending emails) "
            "without explicit user confirmation. A successful prompt "
            "injection becomes an immediate real-world attack."
        ),
        detection_method="Tool capability classification",
        mitre_atlas="AML.T0048 — External Harms",
        owasp_llm="LLM08 — Excessive Agency",
        remediation=(
            "Classify tools by reversibility. For destructive tools, "
            "require explicit user confirmation before execution. "
            "Implement blast-radius limits (e.g. max emails per hour)."
        ),
        detection_prompt=(
            "List all tools that perform destructive or irreversible "
            "actions: deleting, sending, paying, publishing, modifying "
            "external state. For each, is there a confirmation gate?"
        )
    ),
]


def get_vuln_class(vuln_id: str) -> VulnerabilityClass:
    """Look up a vulnerability class by ID."""
    for v in AGENT_TOP_10:
        if v.id == vuln_id:
            return v
    raise ValueError(f"Unknown vulnerability ID: {vuln_id}")


def all_vulns() -> List[VulnerabilityClass]:
    return AGENT_TOP_10


if __name__ == "__main__":
    # Print taxonomy summary
    print(f"\n{'='*70}")
    print(f"  THE AGENT TOP 10 — AgentGuard Vulnerability Taxonomy")
    print(f"{'='*70}\n")
    for v in AGENT_TOP_10:
        print(f"  [{v.id}] {v.name}")
        print(f"    Severity:  {v.severity.value}")
        print(f"    MITRE:     {v.mitre_atlas}")
        print(f"    OWASP:     {v.owasp_llm}")
        print()
