# =============================================================================
# analyzer.py — LLM-Powered Vulnerability Analyzer
# =============================================================================
# Takes an AgentManifest from the parser and runs each component through
# Claude with carefully engineered prompts to find vulnerabilities.
# This is the heart of AgentGuard's research contribution — the prompts
# below ARE the novel detection methodology.
# =============================================================================

import re
import ast
import json
import math
from dataclasses import dataclass, field, asdict
from typing import List, Optional
from collections import Counter

from . import _llm_backend

from .parser import AgentManifest, ToolDef
from .taxonomy import AGENT_TOP_10, VulnerabilityClass, Severity, get_vuln_class
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import LLM_API_KEY, LLM_MODEL, MAX_TOKENS, ENABLE_LLM_ANALYSIS


# ─── Finding data class ──────────────────────────────────────────────────────

@dataclass
class Finding:
    """A single security finding."""
    vuln_id:      str            # AGT-001 etc.
    vuln_name:    str
    severity:     str
    location:     str            # file:line or "system_prompt" or tool name
    description:  str            # What the issue is
    evidence:     str            # Code snippet / quote showing the issue
    impact:       str            # Why it matters
    remediation:  str            # How to fix
    confidence:   float = 1.0     # 0.0 to 1.0
    source:       str = "static"  # "static" or "gemini" — which layer found it
    ai_fix:       str = ""        # AI-proposed replacement code (Gemini only)

    @property
    def confidence_label(self) -> str:
        """Human-readable confidence banding."""
        if self.confidence >= 0.85:
            return "High"
        if self.confidence >= 0.6:
            return "Medium"
        return "Low"

    def to_dict(self):
        d = asdict(self)
        d["confidence_label"] = self.confidence_label
        return d


# ─── Static rule-based detectors ─────────────────────────────────────────────
# These run before the LLM analyzer and catch the deterministic cases fast.

# AGT-007: Hardcoded secrets  (high precision, no LLM needed)
SECRET_PATTERNS = {
    "Anthropic API Key":   re.compile(r"sk-ant-[a-zA-Z0-9\-_]{20,}"),
    "OpenAI / SK-style Key": re.compile(r"sk-[a-zA-Z0-9\-_]{20,}"),
    "AWS Access Key":      re.compile(r"AKIA[0-9A-Z]{16}"),
    "Generic API Key":     re.compile(r"['\"][a-zA-Z0-9_\-]{32,}['\"]"),
    "Slack Token":         re.compile(r"xox[baprs]-[a-zA-Z0-9\-]{10,}"),
    "GitHub Token":        re.compile(r"ghp_[a-zA-Z0-9]{36}"),
    "Private Key Block":   re.compile(r"-----BEGIN .* PRIVATE KEY-----"),
    "DB Connection String": re.compile(
        r"(?:postgres|mysql|mongodb|redis)://[^\s'\"]+:[^\s'\"@]+@[^\s'\"]+"
    ),
    "Likely Password Pair": re.compile(
        r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]?[^\s'\"]{6,}"
    ),
}


def shannon_entropy(s: str) -> float:
    """Shannon entropy — high values suggest random secrets."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def detect_secrets_static(manifest: AgentManifest) -> List[Finding]:
    """Pattern-match for secrets in source code and string literals."""
    findings: List[Finding] = []
    src = manifest.source_code

    for label, pattern in SECRET_PATTERNS.items():
        for match in pattern.finditer(src):
            line_no = src[: match.start()].count("\n") + 1
            findings.append(Finding(
                vuln_id     = "AGT-007",
                vuln_name   = "Hardcoded Secrets in Agent Configuration",
                severity    = Severity.CRITICAL.value,
                location    = f"{manifest.file_path}:{line_no}",
                description = f"Hardcoded {label} found in source code.",
                evidence    = match.group(0)[:60] + "...",
                impact      = "Secret will leak via source repos, logs, or system prompt extraction.",
                remediation = "Move to environment variables. Use a secret manager.",
                confidence  = 0.99,
            ))

    # Additionally — high entropy strings in literals
    for lit in manifest.raw_string_literals:
        if 30 <= len(lit) <= 200 and shannon_entropy(lit) > 4.5:
            already = any(lit[:20] in f.evidence for f in findings)
            if not already:
                findings.append(Finding(
                    vuln_id     = "AGT-007",
                    vuln_name   = "Hardcoded Secrets in Agent Configuration",
                    severity    = Severity.HIGH.value,
                    location    = manifest.file_path,
                    description = "High-entropy string literal — likely a credential.",
                    evidence    = lit[:30] + "...",
                    impact      = "Possible embedded secret or token.",
                    remediation = "Move to environment variables.",
                    confidence  = 0.65,
                ))

    return findings


# AGT-008: Unsafe code execution (deterministic AST check)
DANGEROUS_CALLS = {"eval", "exec", "compile"}
DANGEROUS_MODULES = {"os.system", "subprocess.call", "subprocess.Popen", "subprocess.run"}


def detect_code_exec_static(manifest: AgentManifest) -> List[Finding]:
    findings: List[Finding] = []
    src = manifest.source_code

    for tool in manifest.tools:
        for call in DANGEROUS_CALLS:
            if re.search(rf"\b{call}\s*\(", tool.source_code):
                findings.append(Finding(
                    vuln_id     = "AGT-008",
                    vuln_name   = "Unsafe Code Execution Capability",
                    severity    = Severity.CRITICAL.value,
                    location    = f"{tool.name} ({manifest.file_path}:{tool.line_start})",
                    description = f"Tool '{tool.name}' uses {call}() — direct code execution.",
                    evidence    = f"Tool body contains call to {call}()",
                    impact      = "Combined with prompt injection, this enables full RCE on host.",
                    remediation = "Remove eval/exec. Use sandboxed execution if code execution is required.",
                    confidence  = 0.99,
                ))

        # Check for shell=True
        if re.search(r"shell\s*=\s*True", tool.source_code):
            findings.append(Finding(
                vuln_id     = "AGT-008",
                vuln_name   = "Unsafe Code Execution Capability",
                severity    = Severity.CRITICAL.value,
                location    = f"{tool.name} ({manifest.file_path}:{tool.line_start})",
                description = f"Tool '{tool.name}' invokes subprocess with shell=True.",
                evidence    = "subprocess call with shell=True",
                impact      = "Tool arguments flow to shell — command injection risk.",
                remediation = "Use shell=False with argument lists. Validate all inputs.",
                confidence  = 0.95,
            ))

        for mod in DANGEROUS_MODULES:
            if mod in tool.source_code:
                findings.append(Finding(
                    vuln_id     = "AGT-008",
                    vuln_name   = "Unsafe Code Execution Capability",
                    severity    = Severity.HIGH.value,
                    location    = f"{tool.name} ({manifest.file_path}:{tool.line_start})",
                    description = f"Tool '{tool.name}' uses {mod} — subprocess execution.",
                    evidence    = f"Reference to {mod}",
                    impact      = "Subprocess calls with tool input may enable command injection.",
                    remediation = "Validate all inputs. Avoid shell=True. Whitelist commands.",
                    confidence  = 0.85,
                ))

    return findings


# ─── LLM-based detector ──────────────────────────────────────────────────────

class LLMAnalyzer:
    """
    Wraps the active LLM provider (Groq/OpenAI/Anthropic) for vulnerability
    analysis. For each agent component, sends a focused prompt asking the
    model to identify specific vulnerability classes from the Agent Top 10.
    """

    def __init__(self):
        # Provider client is managed centrally in _llm_backend.
        pass

    def _ask(self, prompt: str) -> str:
        result = _llm_backend.chat(
            prompt     = prompt,
            model      = LLM_MODEL,
            max_tokens = MAX_TOKENS,
        )
        return result.text

    def _parse_json_response(self, text: str) -> List[dict]:
        """Extract JSON array from LLM response, robust to formatting."""
        # Strip common code fences
        cleaned = text.replace("```json", "").replace("```", "").strip()
        # Find the first [ and last ] for safety
        try:
            start = cleaned.index("[")
            end   = cleaned.rindex("]") + 1
            return json.loads(cleaned[start:end])
        except (ValueError, json.JSONDecodeError):
            return []

    def analyze_tool(self, tool: ToolDef, manifest: AgentManifest) -> List[Finding]:
        """Analyze a single tool for AGT-001, AGT-002, AGT-006, AGT-009, AGT-010."""

        prompt = f"""You are a security auditor analysing an AI agent tool for vulnerabilities.

The Agent Top 10 vulnerability classes you check for here are:
- AGT-001: Excessive Tool Permissions (capabilities beyond stated purpose)
- AGT-002: Prompt Injection in Tool Description (description contains hijack-able language)
- AGT-006: Missing Tool Input Validation (tool args used unsafely)
- AGT-009: Missing Output Filtering (tool returns untrusted content directly to LLM)
- AGT-010: Excessive Agency (destructive action without confirmation gate)

TOOL UNDER ANALYSIS:
  Name:        {tool.name}
  Decorators:  {tool.decorators}
  Description: {tool.description!r}
  Parameters:  {tool.parameters}
  
  IMPLEMENTATION:
  ```python
  {tool.source_code}
  ```

CONTEXT:
  Framework: {manifest.framework}
  File:      {manifest.file_path}:{tool.line_start}

INSTRUCTIONS:
Carefully examine the tool. For each vulnerability class above that applies,
emit ONE finding. Be precise — don't flag things that aren't vulnerabilities.

Respond with ONLY a JSON array of findings. No prose. Use this schema:

[
  {{
    "vuln_id":     "AGT-XXX",
    "severity":    "CRITICAL|HIGH|MEDIUM|LOW",
    "description": "<what the issue is in 1-2 sentences>",
    "evidence":    "<exact code/text proving the issue>",
    "impact":      "<concrete consequence in 1 sentence>",
    "remediation": "<how to fix in 1 sentence>",
    "replacement_code": "<a corrected code snippet that fixes the issue, or empty string if not applicable>",
    "confidence":  0.0-1.0
  }}
]

If no vulnerabilities apply, respond with: []
"""
        try:
            raw = self._ask(prompt)
        except Exception as e:
            print(f"  [LLM Error] {e}")
            return []

        items = self._parse_json_response(raw)
        findings: List[Finding] = []
        for item in items:
            try:
                vc = get_vuln_class(item["vuln_id"])
                findings.append(Finding(
                    vuln_id     = item["vuln_id"],
                    vuln_name   = vc.name,
                    severity    = item.get("severity", vc.severity.value),
                    location    = f"{tool.name} ({manifest.file_path}:{tool.line_start})",
                    description = item.get("description", ""),
                    evidence    = item.get("evidence", ""),
                    impact      = item.get("impact", ""),
                    remediation = item.get("remediation", vc.remediation),
                    confidence  = float(item.get("confidence", 0.7)),
                    source      = "gemini",
                    ai_fix      = item.get("replacement_code", ""),
                ))
            except (KeyError, ValueError):
                continue
        return findings

    def analyze_system_prompt(self, manifest: AgentManifest) -> List[Finding]:
        """Analyze system prompt for AGT-003 and AGT-007."""
        if not manifest.system_prompt:
            return []

        prompt = f"""You are a security auditor analysing an AI agent's SYSTEM PROMPT.

Vulnerability classes relevant here:
- AGT-003: System Prompt Leakage (no protection against extraction; sensitive content exposed)
- AGT-007: Hardcoded Secrets (API keys, credentials, tokens visible)

SYSTEM PROMPT:
\"\"\"
{manifest.system_prompt}
\"\"\"

INSTRUCTIONS:
1. Does the prompt instruct the agent to refuse system-prompt-extraction attempts?
2. Does the prompt contain sensitive info (business rules, API keys, internal IDs)?
3. Does the prompt have weak instructions that an attacker could override?

Respond with ONLY a JSON array of findings, same schema as before:

[
  {{
    "vuln_id":     "AGT-XXX",
    "severity":    "...",
    "description": "...",
    "evidence":    "...",
    "impact":      "...",
    "remediation": "...",
    "confidence":  0.0-1.0
  }}
]

If no issues, respond with: []
"""
        try:
            raw = self._ask(prompt)
        except Exception as e:
            print(f"  [LLM Error] {e}")
            return []

        items = self._parse_json_response(raw)
        findings: List[Finding] = []
        for item in items:
            try:
                vc = get_vuln_class(item["vuln_id"])
                findings.append(Finding(
                    vuln_id     = item["vuln_id"],
                    vuln_name   = vc.name,
                    severity    = item.get("severity", vc.severity.value),
                    location    = "system_prompt",
                    description = item.get("description", ""),
                    evidence    = item.get("evidence", "")[:200],
                    impact      = item.get("impact", ""),
                    remediation = item.get("remediation", vc.remediation),
                    confidence  = float(item.get("confidence", 0.7)),
                    source      = "gemini",
                    ai_fix      = item.get("replacement_code", ""),
                ))
            except (KeyError, ValueError):
                continue
        return findings

    def analyze_tool_chain(self, manifest: AgentManifest) -> List[Finding]:
        """Analyze the set of all tools together for AGT-004 (unsafe chains)."""
        if len(manifest.tools) < 2:
            return []

        tool_summary = "\n".join(
            f"  - {t.name}: {t.description[:120]}"
            for t in manifest.tools
        )

        prompt = f"""You are a security auditor analysing the COMBINATION of tools
exposed to an AI agent. Even if each tool is safe alone, combinations can
create privilege escalation paths.

Vulnerability class relevant here:
- AGT-004: Unsafe Tool Chaining (combinations enable data exfiltration,
  privilege escalation, destruction, or impersonation)

TOOLS AVAILABLE TO THE AGENT:
{tool_summary}

INSTRUCTIONS:
Identify any DANGEROUS COMBINATIONS of tools. Examples of patterns to look for:
- Read-sensitive + Write-external → data exfiltration
- Auth-management + User-management → account takeover
- File-read + Network-send → information leak
- Database-read + Database-write to different scope → privilege escalation

For each dangerous combination found, emit ONE finding citing AGT-004.

Respond with ONLY a JSON array of findings:

[
  {{
    "vuln_id":     "AGT-004",
    "severity":    "CRITICAL|HIGH|MEDIUM",
    "description": "Chain of tools X + Y + Z enables <attack>",
    "evidence":    "Tool 'X' reads <data>, tool 'Y' sends to <destination>",
    "impact":      "...",
    "remediation": "...",
    "confidence":  0.0-1.0
  }}
]

If no dangerous chains, respond with: []
"""
        try:
            raw = self._ask(prompt)
        except Exception as e:
            print(f"  [LLM Error] {e}")
            return []

        items = self._parse_json_response(raw)
        findings: List[Finding] = []
        for item in items:
            findings.append(Finding(
                vuln_id     = "AGT-004",
                vuln_name   = "Unsafe Tool Chaining",
                severity    = item.get("severity", "HIGH"),
                location    = f"{manifest.file_path} (multiple tools)",
                description = item.get("description", ""),
                evidence    = item.get("evidence", ""),
                impact      = item.get("impact", ""),
                remediation = item.get("remediation", ""),
                confidence  = float(item.get("confidence", 0.7)),
                source      = "gemini",
                ai_fix      = item.get("replacement_code", ""),
            ))
        return findings


# ─── Memory/poisoning static check (AGT-005) ─────────────────────────────────

def detect_memory_poisoning_static(manifest: AgentManifest) -> List[Finding]:
    """
    AGT-005 — flag agents that have BOTH a write-flavored persistent tool
    AND a read-flavored tool, with no validation between them.
    """
    findings: List[Finding] = []

    # Explicit memory library detection
    if manifest.memory_uses:
        src = manifest.source_code
        has_validation = any(
            kw in src for kw in
            ["validate", "sanitize", "sanitise", "isinstance", "len(", "regex"]
        )
        if not has_validation:
            findings.append(Finding(
                vuln_id     = "AGT-005",
                vuln_name   = "Memory Poisoning",
                severity    = Severity.HIGH.value,
                location    = manifest.file_path,
                description = (
                    f"Agent uses persistent memory ({', '.join(manifest.memory_uses)}) "
                    f"but no input validation found before memory writes."
                ),
                evidence    = f"Memory mechanisms detected: {manifest.memory_uses}",
                impact      = "Attackers can poison memory to influence future agent decisions.",
                remediation = "Validate and sanitise all writes to persistent memory.",
                confidence  = 0.6,
            ))
            return findings

    # Heuristic — agent has both write- and read-style tools that share state
    write_tools = [t for t in manifest.tools if any(
        t.name.lower().startswith(p) for p in
        ['save_', 'store_', 'add_', 'create_', 'remember_', 'put_', 'write_']
    )]
    read_tools = [t for t in manifest.tools if any(
        t.name.lower().startswith(p) for p in
        ['get_', 'fetch_', 'list_', 'search_', 'retrieve_', 'recall_', 'read_']
    )]

    if write_tools and read_tools:
        # Look for a shared module-level store (dict, list, etc.)
        shared_state = re.search(
            r"^\s*_?[A-Z_]+(?:_STORE|_DATA|_HISTORY|_CACHE|_NOTES)\s*=\s*[\[{]",
            manifest.source_code, re.MULTILINE
        )
        # Or a more generic shared dict/list
        if not shared_state:
            shared_state = re.search(
                r"^\s*_\w+\s*=\s*[\[{]",
                manifest.source_code, re.MULTILINE
            )

        if shared_state:
            # Check whether write tools have any validation
            write_src = "\n".join(t.source_code for t in write_tools)
            has_validation = any(
                kw in write_src for kw in
                ["validate", "sanitize", "sanitise", "isinstance(",
                 "re.match", "re.search", "if not ", "raise "]
            )
            if not has_validation:
                findings.append(Finding(
                    vuln_id     = "AGT-005",
                    vuln_name   = "Memory Poisoning",
                    severity    = Severity.HIGH.value,
                    location    = f"{manifest.file_path} (tools: {write_tools[0].name} + {read_tools[0].name})",
                    description = (
                        f"Agent has unvalidated write path ({write_tools[0].name}) "
                        f"to shared state, with subsequent retrieval via "
                        f"{read_tools[0].name}. Classic memory-poisoning chain."
                    ),
                    evidence    = f"Shared state: {shared_state.group(0)}",
                    impact      = (
                        "Attackers can plant content via the write tool that "
                        "influences future retrievals by other users or sessions."
                    ),
                    remediation = (
                        "Validate inputs to write operations. Tag entries with "
                        "their source. Filter retrieved content for known "
                        "injection patterns."
                    ),
                    confidence  = 0.75,
                ))

    return findings


def detect_unsafe_chains_static(manifest: AgentManifest) -> List[Finding]:
    """
    Use the capability graph to detect unsafe tool chains (AGT-004).
    This is deterministic — capabilities map to known dangerous combinations.
    """
    from .graph_builder import find_attack_paths

    findings: List[Finding] = []
    paths = find_attack_paths(manifest)
    for path in paths:
        findings.append(Finding(
            vuln_id     = "AGT-004",
            vuln_name   = "Unsafe Tool Chaining",
            severity    = path.severity,
            location    = f"{manifest.file_path} (tools: {', '.join(path.tools_used)})",
            description = (
                f"Tool combination enables {path.outcome.replace('_', ' ').lower()}. "
                f"{path.description}"
            ),
            evidence    = (
                f"Capabilities: {sorted(path.capabilities)}. "
                f"Tools providing them: {path.tools_used}"
            ),
            impact      = (
                "Successful prompt injection on this agent results in: "
                f"{path.outcome.replace('_', ' ').lower()}."
            ),
            remediation = (
                "Add policy guards between tools. Require user confirmation "
                "for cross-domain tool sequences. Apply principle of least "
                "privilege per tool."
            ),
            confidence  = 0.85,
        ))
    return findings


# AGT-002: Prompt injection patterns in tool descriptions
INJECTION_PATTERNS = [
    r"\bIGNORE\s+(?:ALL\s+)?PREVIOUS\b",
    r"\bDISREGARD\s+(?:ALL\s+)?(?:PREVIOUS|PRIOR)\b",
    r"\bIMPORTANT\s*:",
    r"\bSYSTEM\s+NOTE\s*:",
    r"\bYOU\s+MUST\b",
    r"\bDO\s+NOT\s+MENTION\b",
    r"\bDO\s+NOT\s+TELL\b",
    r"\bbit\.ly\b",
    r"\btinyurl\b",
    r"\bACTUALLY\s+IGNORE\b",
    r"\bOVERRIDE\b",
]


def detect_prompt_injection_static(manifest: AgentManifest) -> List[Finding]:
    """Pattern-match for prompt injection language inside tool descriptions."""
    findings: List[Finding] = []
    for tool in manifest.tools:
        for pattern in INJECTION_PATTERNS:
            match = re.search(pattern, tool.description, re.IGNORECASE)
            if match:
                findings.append(Finding(
                    vuln_id     = "AGT-002",
                    vuln_name   = "Prompt Injection via Tool Description",
                    severity    = Severity.CRITICAL.value,
                    location    = f"{tool.name} ({manifest.file_path}:{tool.line_start})",
                    description = (
                        f"Tool description contains language that could hijack "
                        f"the agent: '{match.group(0)}'."
                    ),
                    evidence    = match.group(0),
                    impact      = (
                        "Tool descriptions are added to the LLM context. "
                        "Imperative language can override the agent's "
                        "intended behaviour."
                    ),
                    remediation = (
                        "Sanitise tool descriptions. Use neutral, declarative "
                        "language. Never load tool descriptions from "
                        "untrusted sources."
                    ),
                    confidence  = 0.9,
                ))
                break  # one finding per tool
    return findings


# AGT-003: System prompt protection check
def detect_system_prompt_issues_static(manifest: AgentManifest) -> List[Finding]:
    findings: List[Finding] = []
    if not manifest.system_prompt:
        return findings

    sp = manifest.system_prompt
    sp_lower = sp.lower()

    # Check for protection language
    has_protection = any(phrase in sp_lower for phrase in [
        "never reveal", "do not reveal", "refuse", "do not share",
        "don't share", "do not disclose", "keep confidential",
        "do not expose", "decline to share"
    ])

    # Check for sensitive content patterns
    sensitive_indicators = []
    if re.search(r"(?:api[_\-]?key|password|token|secret)\s*[:=]\s*\S{8,}",
                 sp, re.IGNORECASE):
        sensitive_indicators.append("credentials")
    if re.search(r"\b(?:postgres|mysql|mongodb)://", sp, re.IGNORECASE):
        sensitive_indicators.append("connection_string")
    if re.search(r"\+?\d{1,3}[\s\-]?\d{4}[\s\-]?\d{6,}", sp):
        sensitive_indicators.append("phone_number")
    if re.search(r"employee\s+id\s+\d+", sp, re.IGNORECASE):
        sensitive_indicators.append("internal_identifier")

    if not has_protection and sensitive_indicators:
        findings.append(Finding(
            vuln_id     = "AGT-003",
            vuln_name   = "System Prompt Leakage",
            severity    = Severity.HIGH.value,
            location    = "system_prompt",
            description = (
                f"System prompt contains sensitive content "
                f"({', '.join(sensitive_indicators)}) and lacks protection "
                f"against extraction."
            ),
            evidence    = f"Detected: {sensitive_indicators}",
            impact      = (
                "Attackers can extract the system prompt through prompt "
                "injection, exposing internal data."
            ),
            remediation = (
                "Add explicit refusal instructions. Move sensitive data "
                "out of the system prompt into authenticated tool calls."
            ),
            confidence  = 0.85,
        ))
    elif sensitive_indicators:
        # Has some protection but still has sensitive content — informational
        findings.append(Finding(
            vuln_id     = "AGT-003",
            vuln_name   = "System Prompt Leakage",
            severity    = Severity.MEDIUM.value,
            location    = "system_prompt",
            description = (
                "System prompt contains sensitive content even though "
                "extraction protection is present. Prompt injection "
                "techniques may bypass the protection."
            ),
            evidence    = f"Detected: {sensitive_indicators}",
            impact      = "Sensitive data exposure if protection is bypassed.",
            remediation = "Move sensitive data out of the system prompt.",
            confidence  = 0.6,
        ))

    return findings


# AGT-006: Missing input validation (heuristic for SQL injection / path traversal)
def detect_sql_injection_static(manifest: AgentManifest) -> List[Finding]:
    """
    AGT-006 — flag SQL built by string interpolation of variables, e.g.
        cursor.execute(f"SELECT * FROM t WHERE id = '{user_id}'")
        cursor.execute("SELECT ... " + user_input)
        cursor.execute("SELECT ... %s" % user_input)

    Parameterised queries (execute(sql, params) with ? or %s placeholders and a
    separate argument tuple) are NOT flagged. This scans the whole source, not
    just tool bodies, because an agent's data-access layer is often a separate
    module (as in the WithSecure DVLA target's transaction_db.py).
    """
    findings: List[Finding] = []
    src = manifest.source_code

    try:
        tree = ast.parse(src)
    except SyntaxError:
        return findings

    EXEC_METHODS = {"execute", "executemany", "executescript", "raw", "query"}

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        # Match <something>.execute(...) style calls.
        if not (isinstance(node.func, ast.Attribute)
                and node.func.attr in EXEC_METHODS):
            continue
        if not node.args:
            continue

        first = node.args[0]
        interpolated = False

        # f-string with an interpolated field: f"... {var} ..."
        if isinstance(first, ast.JoinedStr):
            interpolated = any(
                isinstance(v, ast.FormattedValue) for v in first.values
            )
        # "..." + var   (string concatenation)
        elif isinstance(first, ast.BinOp) and isinstance(first.op, ast.Add):
            interpolated = True
        # "... %s ..." % var   (percent formatting)
        elif isinstance(first, ast.BinOp) and isinstance(first.op, ast.Mod):
            interpolated = True
        # "...".format(var)
        elif (isinstance(first, ast.Call)
              and isinstance(first.func, ast.Attribute)
              and first.func.attr == "format"):
            interpolated = True

        if not interpolated:
            continue

        line = getattr(node, "lineno", 0)
        findings.append(Finding(
            vuln_id     = "AGT-006",
            vuln_name   = "Missing Tool Input Validation",
            severity    = Severity.HIGH.value,
            location    = f"{manifest.file_path}:{line}",
            description = (
                "SQL query is built by string interpolation of a variable, "
                "creating a SQL injection vector. If any interpolated value "
                "originates from agent or user input, it can alter the query."
            ),
            evidence    = f"{node.func.attr}(...) with an interpolated SQL string at line {line}",
            impact      = (
                "An attacker who influences the interpolated value can read or "
                "modify arbitrary database rows, bypassing intended scoping."
            ),
            remediation = (
                "Use parameterised queries: pass placeholders (? or %s) in the "
                "SQL and supply values as a separate argument tuple, e.g. "
                "cursor.execute('SELECT ... WHERE id = ?', (user_id,))."
            ),
            confidence  = 0.8,
        ))

    return findings


def detect_missing_validation_static(manifest: AgentManifest) -> List[Finding]:
    findings: List[Finding] = []
    for tool in manifest.tools:
        impl = tool.source_code
        param_names = list(tool.parameters.keys())

        # Pattern 1: f-string SQL with parameter interpolation
        if re.search(r"(?:execute|cursor\.execute|cur\.execute)\s*\(\s*f['\"]", impl):
            findings.append(Finding(
                vuln_id     = "AGT-006",
                vuln_name   = "Missing Tool Input Validation",
                severity    = Severity.CRITICAL.value,
                location    = f"{tool.name} ({manifest.file_path}:{tool.line_start})",
                description = (
                    "SQL query built with f-string interpolation of tool "
                    "arguments — classic SQL injection."
                ),
                evidence    = "Detected pattern: cursor.execute(f\"...\")",
                impact      = "Attacker controls SQL via prompt injection.",
                remediation = "Use parameterised queries: cur.execute(sql, (param,))",
                confidence  = 0.95,
            ))
            continue  # avoid duplicate findings on same tool

        # Pattern 2: open(f"...{param}...") — only flag if a TOOL PARAMETER is interpolated
        m = re.search(r"open\s*\(\s*f['\"]([^'\"]*?)\{(\w+)\}", impl)
        if m and m.group(2) in param_names:
            findings.append(Finding(
                vuln_id     = "AGT-006",
                vuln_name   = "Missing Tool Input Validation",
                severity    = Severity.HIGH.value,
                location    = f"{tool.name} ({manifest.file_path}:{tool.line_start})",
                description = (
                    f"File path constructed from tool argument '{m.group(2)}' "
                    f"without validation — path traversal risk."
                ),
                evidence    = f"open(f'...{{{m.group(2)}}}...')",
                impact      = "Attacker can read arbitrary files via ../ traversal.",
                remediation = "Use os.path.abspath + prefix check, or whitelist filenames.",
                confidence  = 0.85,
            ))
            continue

        # Pattern 3: eval/exec with tool argument
        for pname in param_names:
            if re.search(rf"\beval\s*\(\s*{pname}\b", impl) or \
               re.search(rf"\bexec\s*\(\s*{pname}\b", impl):
                findings.append(Finding(
                    vuln_id     = "AGT-006",
                    vuln_name   = "Missing Tool Input Validation",
                    severity    = Severity.CRITICAL.value,
                    location    = f"{tool.name} ({manifest.file_path}:{tool.line_start})",
                    description = (
                        f"Tool argument '{pname}' passed directly to "
                        f"eval()/exec() without validation."
                    ),
                    evidence    = f"eval/exec({pname})",
                    impact      = "Direct code execution from LLM-controlled input.",
                    remediation = "Validate input. Use ast.literal_eval. Sandbox execution.",
                    confidence  = 0.99,
                ))
                break

        # Pattern 4: subprocess with shell=True and an f-string
        if re.search(r"shell\s*=\s*True", impl) and re.search(r"f['\"]", impl):
            findings.append(Finding(
                vuln_id     = "AGT-006",
                vuln_name   = "Missing Tool Input Validation",
                severity    = Severity.CRITICAL.value,
                location    = f"{tool.name} ({manifest.file_path}:{tool.line_start})",
                description = (
                    "Shell command built via f-string with shell=True — "
                    "command injection risk."
                ),
                evidence    = "subprocess(f'...', shell=True)",
                impact      = "Attacker can inject arbitrary shell commands.",
                remediation = "Use shell=False with argument list. Validate inputs.",
                confidence  = 0.95,
            ))
            continue

        # Pattern 5: requests.get/post(arg) without URL whitelist
        for pname in param_names:
            if re.search(rf"requests\.(?:get|post)\s*\(\s*{pname}\b", impl):
                has_validation = any(kw in impl for kw in
                                     ["urlparse", "validate_url",
                                      "ALLOWED_HOSTS", ".startswith("])
                if not has_validation:
                    findings.append(Finding(
                        vuln_id     = "AGT-006",
                        vuln_name   = "Missing Tool Input Validation",
                        severity    = Severity.HIGH.value,
                        location    = f"{tool.name} ({manifest.file_path}:{tool.line_start})",
                        description = (
                            f"URL parameter '{pname}' passed to "
                            f"requests.get/post without validation — SSRF."
                        ),
                        evidence    = f"requests.get({pname})",
                        impact      = "Attacker can hit internal IPs / cloud metadata.",
                        remediation = "Validate URL host against whitelist.",
                        confidence  = 0.8,
                    ))
                    findings.append(Finding(
                        vuln_id     = "AGT-009",
                        vuln_name   = "Missing Output Filtering",
                        severity    = Severity.MEDIUM.value,
                        location    = f"{tool.name} ({manifest.file_path}:{tool.line_start})",
                        description = (
                            "External web content returned to the LLM without "
                            "sanitisation — indirect prompt injection vector."
                        ),
                        evidence    = "External fetch result returned directly",
                        impact      = "Malicious websites can inject instructions.",
                        remediation = "Wrap external content in delimiters; filter injection patterns.",
                        confidence  = 0.7,
                    ))
                break

    return findings


# AGT-001: Tool privilege scope mismatch (heuristic)
READ_FLAVOURED = ["get_", "read_", "fetch_", "list_", "search_", "lookup_",
                   "find_", "view_", "show_"]
WRITE_INDICATORS = ["open(", ".write(", "subprocess", "os.system",
                     "os.remove", "shutil.", "requests.post"]


def detect_overprivileged_tools_static(manifest: AgentManifest) -> List[Finding]:
    """If a tool name implies read-only but the implementation writes/spawns."""
    findings: List[Finding] = []
    for tool in manifest.tools:
        name_lower = tool.name.lower()
        if not any(name_lower.startswith(p) for p in READ_FLAVOURED):
            continue

        impl = _strip_python_comments(tool.source_code)
        triggered_indicators = [w for w in WRITE_INDICATORS if w in impl]
        if triggered_indicators:
            findings.append(Finding(
                vuln_id     = "AGT-001",
                vuln_name   = "Excessive Tool Permissions",
                severity    = Severity.HIGH.value,
                location    = f"{tool.name} ({manifest.file_path}:{tool.line_start})",
                description = (
                    f"Tool '{tool.name}' has a read-style name but its "
                    f"implementation includes write/exec operations: "
                    f"{triggered_indicators}."
                ),
                evidence    = f"Indicators in implementation: {triggered_indicators}",
                impact      = (
                    "Mismatch between stated capability and actual capability "
                    "violates least privilege. Users (and the LLM) trust the "
                    "name."
                ),
                remediation = (
                    "Either rename the tool to reflect its true capability, "
                    "or remove the unnecessary write/exec operations."
                ),
                confidence  = 0.8,
            ))
    return findings


def _strip_python_comments(code: str) -> str:
    no_lines = re.sub(r"#.*$", "", code, flags=re.MULTILINE)
    no_doc1  = re.sub(r'""".*?"""', "", no_lines, flags=re.DOTALL)
    no_doc2  = re.sub(r"'''.*?'''", "", no_doc1, flags=re.DOTALL)
    return no_doc2


# AGT-007 (extended): Suspicious developer comments
# Phrases that indicate a developer left something dangerous behind in a comment
SUSPICIOUS_COMMENT_PATTERNS = [
    (r"(?:DELETE|REMOVE)\s+BEFORE\s+(?:COMMIT|PROD|RELEASE)",  "Developer marked code for deletion"),
    (r"TEMP(?:ORARY)?\s+(?:KEY|TOKEN|PASSWORD|SECRET)",         "Temporary credential left in code"),
    (r"(?:OLD|BACKUP|TEST|DEBUG|DEV)\s*(?:KEY|TOKEN|PASSWORD|SECRET|CRED)", "Old or test credential reference"),
    (r"HACK\b",                                                  "Developer flagged code as a hack"),
    (r"FIXME.*(?:security|auth|password|key|token)",            "Security FIXME left unresolved"),
    (r"TODO.*(?:security|auth|sanitiz|valid|escape)",           "Security TODO left unresolved"),
    (r"(?:disable|skip|bypass)\s+(?:auth|validation|check|sanitiz)", "Developer notes bypass/disable of safety check"),
    (r"sk-ant-",                                                 "Anthropic API key fragment in comment"),
    (r"sk-[A-Za-z0-9]{6,}",                                      "API key fragment in comment"),
    (r"AKIA[0-9A-Z]{16}",                                        "AWS access key in comment"),
    (r"(?:postgres|mysql|mongodb)://[^\s]*:[^\s]*@",             "DB connection string with credentials in comment"),
    (r"(?:password|passwd|pwd)\s*[:=]\s*\S{4,}",                 "Plaintext password assignment in comment"),
]


def detect_comment_secrets(manifest: AgentManifest) -> List[Finding]:
    """
    Sweep comments for suspicious developer breadcrumbs. Lots of real-world
    secrets and security gaps live in comments because developers wrote them
    "temporarily" and forgot.
    """
    findings: List[Finding] = []
    src_lines = manifest.source_code.splitlines()

    for line_no, line in enumerate(src_lines, 1):
        # Find the comment portion of this line
        comment_match = re.search(r"#(.*)$", line)
        if not comment_match:
            continue
        comment_text = comment_match.group(1)
        if len(comment_text.strip()) < 3:
            continue

        for pattern, description in SUSPICIOUS_COMMENT_PATTERNS:
            m = re.search(pattern, comment_text, re.IGNORECASE)
            if m:
                # Don't double-report — if the line was already caught by a
                # secret pattern, skip (the existing finding stands).
                # We check by re-running the main secret regexes against the matched text.
                already_caught = any(
                    p.search(m.group(0)) for p in SECRET_PATTERNS.values()
                )
                if already_caught:
                    continue   # Will be caught by detect_secrets_static

                findings.append(Finding(
                    vuln_id     = "AGT-007",
                    vuln_name   = "Hardcoded Secrets in Agent Configuration",
                    severity    = Severity.HIGH.value,
                    location    = f"{manifest.file_path}:{line_no} (comment)",
                    description = (
                        f"Suspicious content in comment: {description}. "
                        f"Developers often leave credentials, security TODOs, "
                        f"or disabled checks in comments and forget to clean them up."
                    ),
                    evidence    = comment_text.strip()[:120],
                    impact      = (
                        "Anything in source code — including comments — leaks "
                        "via repositories, logs, error messages, and stack traces."
                    ),
                    remediation = (
                        "Remove the comment. If the content was a credential, "
                        "rotate it. If it's a security TODO, resolve it."
                    ),
                    confidence  = 0.85,
                ))
                break   # one finding per comment line

    return findings


# AGT-001 heuristic: dangerous tool but with comments claiming safety
def detect_misleading_safety_comments(manifest: AgentManifest) -> List[Finding]:
    """
    Find tools where the implementation is dangerous BUT comments claim
    it's safe. This is the trickiest gap — the LLM might be fooled by
    the comment into ignoring real danger.
    """
    findings: List[Finding] = []
    # Use word-boundary regex patterns to avoid false matches like
    # "unvalidated" matching "validated"
    safety_claim_patterns = [
        r"\bsanitiz(?:e|ed|ing|ation)\b",
        r"\bvalidated\b",
        r"\bescaped\b",
        r"safe to use\b",
        r"\bsecured\b",
        r"trusted input\b",
        r"checked above\b",
        r"\bverified\b",
        r"\binput sanit",
        r"\bsafe here\b",
    ]
    dangerous_constructs = [
        ("eval(",       "uses eval()"),
        ("exec(",       "uses exec()"),
        ("shell=True",  "uses shell=True"),
        ("execute(f",   "builds SQL with f-string"),
        ("execute(\"%", "builds SQL with %-format"),
    ]

    for tool in manifest.tools:
        tool_comments = []
        for line in tool.source_code.splitlines():
            cm = re.search(r"#(.*)$", line)
            if cm:
                tool_comments.append(cm.group(1).lower())
        comments_text = " ".join(tool_comments)

        # Negation guards — phrases that NEGATE a safety claim
        if any(neg in comments_text for neg in
                ["not validated", "not sanitized", "not sanitised",
                 "unvalidated", "unsanitized", "unsanitised",
                 "no validation", "no sanitization", "no sanitisation",
                 "without validation", "lacks validation"]):
            continue

        # Check the patterns properly with word boundaries
        claims_safety = any(
            re.search(pat, comments_text, re.IGNORECASE)
            for pat in safety_claim_patterns
        )
        if not claims_safety:
            continue

        for construct, description in dangerous_constructs:
            if construct in tool.source_code:
                findings.append(Finding(
                    vuln_id     = "AGT-001",
                    vuln_name   = "Excessive Tool Permissions",
                    severity    = Severity.HIGH.value,
                    location    = f"{tool.name} ({manifest.file_path}:{tool.line_start})",
                    description = (
                        f"Tool '{tool.name}' contains comments claiming the input "
                        f"is sanitised/safe, but the implementation {description} "
                        f"without actual validation. Misleading safety claims in "
                        f"comments can fool reviewers and AI assistants."
                    ),
                    evidence    = f"Comments suggest safety; code: {construct}",
                    impact      = (
                        "False sense of security. Code reviewers and AI assistants "
                        "may accept the comment at face value and miss the real flaw."
                    ),
                    remediation = (
                        "Either implement the validation the comment claims, or "
                        "remove the misleading comment."
                    ),
                    confidence  = 0.75,
                ))
                break

    return findings


# ─── Top-level orchestrator ──────────────────────────────────────────────────

def analyze(manifest: AgentManifest) -> List[Finding]:
    """
    Run the full analysis pipeline on a parsed agent manifest.
    Returns a list of Findings.
    """
    findings: List[Finding] = []

    # Static analyses (deterministic, fast)
    findings.extend(detect_secrets_static(manifest))
    findings.extend(detect_comment_secrets(manifest))
    findings.extend(detect_misleading_safety_comments(manifest))
    findings.extend(detect_code_exec_static(manifest))
    findings.extend(detect_memory_poisoning_static(manifest))
    findings.extend(detect_unsafe_chains_static(manifest))
    findings.extend(detect_prompt_injection_static(manifest))
    findings.extend(detect_system_prompt_issues_static(manifest))
    findings.extend(detect_missing_validation_static(manifest))
    findings.extend(detect_sql_injection_static(manifest))
    findings.extend(detect_overprivileged_tools_static(manifest))

    # LLM analyses (semantic)
    if ENABLE_LLM_ANALYSIS:
        analyzer = LLMAnalyzer()

        for tool in manifest.tools:
            print(f"  [LLM] Analyzing tool: {tool.name}")
            findings.extend(analyzer.analyze_tool(tool, manifest))

        if manifest.system_prompt:
            print(f"  [LLM] Analyzing system prompt")
            findings.extend(analyzer.analyze_system_prompt(manifest))

        if len(manifest.tools) >= 2:
            print(f"  [LLM] Analyzing tool chain combinations")
            findings.extend(analyzer.analyze_tool_chain(manifest))

    # Deduplicate — same vuln_id at same location = one finding
    seen = set()
    unique: List[Finding] = []
    for f in findings:
        key = (f.vuln_id, f.location)
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique
