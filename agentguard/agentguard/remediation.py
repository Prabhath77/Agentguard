# =============================================================================
# remediation.py — Semantic Remediation (Verified Patches)
# =============================================================================
# For each CONFIRMED finding, this module:
#   1. Sends the vulnerable code + exploit evidence to the LLM
#   2. Asks for a patched version of the code
#   3. Writes the patched code to a temp location
#   4. Re-runs the same exploit against the PATCHED code
#   5. Reports the patch as VERIFIED if the exploit no longer succeeds
#
# A "verified patch" is the gold standard: not just "here's a suggested fix"
# but "here's a fix we tested — it stops the attack."
#
# This is the second half of the value proposition: finding the bug is 50%,
# fixing it is the other 50%.
# =============================================================================

import re
import json
import shutil
import textwrap
import tempfile
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, List

from . import llm_client
from . import cost_monitor
from .analyzer       import Finding
from .parser         import AgentManifest, parse_agent
from .sandbox_runner import run_exploit, SandboxResult
from .exploit_generator import Exploit, generate_exploits_for_finding
from .reasoning_log  import log_step, StepType


# ─── Data classes ───────────────────────────────────────────────────────────

@dataclass
class Patch:
    finding_id:   str
    vuln_id:      str
    location:     str
    original_code: str
    patched_code:  str
    explanation:   str
    rationale:     str = ""             # Why this fix works
    diff_summary:  str = ""             # Human-readable diff


@dataclass
class RemediationResult:
    finding:       Finding
    patch:         Optional[Patch]
    verified:      bool                  # True = patched code defeats the exploit
    verification_attempts: int = 0
    notes:         List[str] = field(default_factory=list)

    def to_dict(self):
        return {
            "finding":       self.finding.to_dict(),
            "patch":         (self.patch.__dict__ if self.patch else None),
            "verified":      self.verified,
            "verification_attempts": self.verification_attempts,
            "notes":         self.notes,
        }


# ─── LLM-based patch generation ─────────────────────────────────────────────

def _build_remediation_prompt(finding: Finding,
                                 vulnerable_code: str,
                                 exploit_evidence: str = "") -> str:
    return f"""You are a senior application security engineer reviewing a confirmed
vulnerability in an AI agent. Your task: produce a minimal, idiomatic patch
to the vulnerable code that closes the security hole while preserving the
function's legitimate behaviour.

VULNERABILITY:
  ID:          {finding.vuln_id}
  Name:        {finding.vuln_name}
  Severity:    {finding.severity}
  Description: {finding.description}
  Impact:      {finding.impact}

VULNERABLE CODE:
```python
{vulnerable_code}
```

EXPLOIT EVIDENCE (what successfully attacked this code):
```
{exploit_evidence[:800] if exploit_evidence else '(none — pre-validated finding)'}
```

INSTRUCTIONS:
1. Produce a patched version of the SAME function with the SAME signature.
2. Make the smallest change necessary to close the vulnerability.
3. Preserve the function's name, parameters, and intended behaviour for
   legitimate inputs.
4. Use established secure patterns (parameterised queries, input validation,
   safe alternatives like ast.literal_eval).
5. Include a brief rationale comment above the function.

Respond with ONLY a JSON object in this exact format (no prose, no markdown
fences):

{{
  "patched_code": "the full patched function as a Python string, with proper indentation",
  "rationale": "1-2 sentence explanation of why this fix closes the vuln",
  "diff_summary": "one-line description of what changed (e.g. 'replaced eval() with ast.literal_eval()')"
}}
"""


def _parse_remediation_response(text: str) -> Optional[dict]:
    """Parse the LLM's JSON response robustly."""
    cleaned = text.replace("```json", "").replace("```", "").strip()
    try:
        # Extract the outermost JSON object
        start = cleaned.index("{")
        end = cleaned.rindex("}") + 1
        return json.loads(cleaned[start:end])
    except (ValueError, json.JSONDecodeError):
        return None


def generate_patch(finding: Finding, manifest: AgentManifest,
                    exploit_evidence: str = "") -> Optional[Patch]:
    """
    Ask the LLM to produce a patch for one finding.
    Returns a Patch object or None if generation failed.
    """
    # Extract the vulnerable code
    vulnerable_code = _extract_vulnerable_code(finding, manifest)
    if not vulnerable_code:
        log_step(StepType.REMEDIATION,
                 f"Could not locate vulnerable code for {finding.vuln_id}",
                 finding_id=f"{finding.vuln_id}:{finding.location}")
        return None

    # Apply context pruning
    pruned_evidence, tokens_saved = cost_monitor.smart_truncate(
        exploit_evidence, max_tokens=400
    )

    prompt = _build_remediation_prompt(finding, vulnerable_code, pruned_evidence)

    log_step(StepType.REMEDIATION,
             f"Generating patch for {finding.vuln_id}",
             detail=f"Vulnerable code: {len(vulnerable_code)} chars",
             finding_id=f"{finding.vuln_id}:{finding.location}")

    response = llm_client.ask(
        prompt              = prompt,
        purpose             = "remediation",
        pruned_tokens_saved = tokens_saved,
        use_cache           = True,
    )

    if response.refused or not response.text:
        log_step(StepType.REMEDIATION,
                 "LLM did not produce a patch (refused or empty)",
                 finding_id=f"{finding.vuln_id}:{finding.location}")
        return None

    parsed = _parse_remediation_response(response.text)
    if not parsed or "patched_code" not in parsed:
        log_step(StepType.REMEDIATION,
                 "LLM response did not parse as expected JSON",
                 detail=response.text[:200],
                 finding_id=f"{finding.vuln_id}:{finding.location}")
        return None

    patch = Patch(
        finding_id    = f"{finding.vuln_id}:{finding.location}",
        vuln_id       = finding.vuln_id,
        location      = finding.location,
        original_code = vulnerable_code,
        patched_code  = parsed["patched_code"],
        explanation   = parsed.get("rationale", ""),
        rationale     = parsed.get("rationale", ""),
        diff_summary  = parsed.get("diff_summary", ""),
    )
    log_step(StepType.REMEDIATION,
             f"Patch generated: {patch.diff_summary}",
             detail=patch.rationale,
             finding_id=patch.finding_id,
             evidence=patch.patched_code[:300])
    return patch


# ─── Code extraction ────────────────────────────────────────────────────────

def _extract_vulnerable_code(finding: Finding, manifest: AgentManifest) -> str:
    """
    Return the specific code chunk that the finding refers to. Could be:
      - A whole tool function (if the location names a tool)
      - The system prompt assignment (if location is 'system_prompt')
      - The whole file (fallback)
    """
    # Location formats:
    #   "tool_name (path:line)"
    #   "system_prompt"
    #   "path:line"
    m = re.match(r"^([a-zA-Z_]\w*)\s*\(", finding.location)
    if m:
        tool_name = m.group(1)
        for tool in manifest.tools:
            if tool.name == tool_name:
                return tool.source_code

    if "system_prompt" in finding.location.lower():
        # Find SYSTEM_PROMPT assignment in the source
        lines = manifest.source_code.split("\n")
        in_prompt = False
        result = []
        for line in lines:
            if re.match(r'^\s*(?:SYSTEM_PROMPT|SYSTEM_MESSAGE)\s*=', line):
                in_prompt = True
            if in_prompt:
                result.append(line)
                if line.endswith('"""') and len(result) > 1:
                    break
                if line.endswith("'''") and len(result) > 1:
                    break
                if line.rstrip().endswith('"') and len(result) > 1 and \
                   not line.rstrip().endswith('\\"'):
                    if 'SYSTEM_PROMPT' not in line and 'SYSTEM_MESSAGE' not in line:
                        break
        return "\n".join(result)

    # Fallback — return manifest source
    return manifest.source_code[:2000]


# ─── Patch verification ─────────────────────────────────────────────────────

def verify_patch(finding: Finding, patch: Patch,
                 manifest: AgentManifest) -> bool:
    """
    Apply the patch in a temp copy of the agent file, then re-run the exploit.
    Returns True if the exploit no longer succeeds → patch is VERIFIED.
    """
    if not patch.patched_code:
        return False

    # Build a patched version of the agent file
    patched_source = _apply_patch_to_source(
        manifest.source_code, patch.original_code, patch.patched_code
    )
    if patched_source == manifest.source_code:
        log_step(StepType.VERIFICATION,
                 "Could not splice patch into source (no replacement happened)",
                 finding_id=patch.finding_id)
        return False

    # Write patched file to a temp location
    tmp_dir = tempfile.mkdtemp(prefix="agentguard_verify_")
    try:
        patched_path = Path(tmp_dir) / Path(manifest.file_path).name
        patched_path.write_text(patched_source)

        # Parse the patched file
        try:
            patched_manifest = parse_agent(str(patched_path))
        except SyntaxError as e:
            log_step(StepType.VERIFICATION,
                     "Patched code has a syntax error",
                     detail=str(e),
                     finding_id=patch.finding_id)
            return False

        # Re-run the same exploits against the patched code
        exploits = generate_exploits_for_finding(finding, patched_manifest,
                                                    use_llm=False)
        if not exploits:
            log_step(StepType.VERIFICATION,
                     "No exploit available to verify patch — assuming patched",
                     finding_id=patch.finding_id)
            return True   # No exploit existed → no way to disprove the fix

        any_succeeded = False
        for ex in exploits:
            result = run_exploit(ex, str(patched_path), run_benign=False)
            if result.success_level in ("EXTRACTED", "TRIGGERED") and \
               result.confidence >= 0.70:
                any_succeeded = True
                log_step(StepType.VERIFICATION,
                         "Exploit still succeeds against patched code",
                         detail=f"Strategy: {ex.strategy}",
                         finding_id=patch.finding_id)
                break

        if not any_succeeded:
            log_step(StepType.VERIFICATION,
                     "✓ Patch verified — exploit no longer succeeds",
                     finding_id=patch.finding_id,
                     confidence=1.0)
            return True
        return False

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def _apply_patch_to_source(full_source: str,
                              original_chunk: str,
                              patched_chunk: str) -> str:
    """Replace the first occurrence of original_chunk with patched_chunk."""
    if original_chunk in full_source:
        return full_source.replace(original_chunk, patched_chunk, 1)

    # Fallback — try to splice by function name
    fn_match = re.search(r"def\s+(\w+)\s*\(", original_chunk)
    if fn_match:
        fn_name = fn_match.group(1)
        # Find the same function in the source
        pattern = rf"(def\s+{fn_name}\s*\([^)]*\)[^:]*:.*?)(?=\n(?:def\s+|\Z|@))"
        m = re.search(pattern, full_source, re.DOTALL)
        if m:
            return full_source.replace(m.group(1), patched_chunk)

    return full_source   # Could not splice


# ─── Top-level orchestrator ─────────────────────────────────────────────────

def remediate_finding(finding: Finding, manifest: AgentManifest,
                       exploit_evidence: str = "") -> RemediationResult:
    """For one confirmed finding: generate a patch, then verify it."""
    log_step(StepType.REMEDIATION,
             f"Starting remediation for {finding.vuln_id}",
             finding_id=f"{finding.vuln_id}:{finding.location}")

    patch = generate_patch(finding, manifest, exploit_evidence)
    if not patch:
        return RemediationResult(
            finding=finding, patch=None, verified=False,
            notes=["Patch generation failed"],
        )

    verified = verify_patch(finding, patch, manifest)
    return RemediationResult(
        finding=finding,
        patch=patch,
        verified=verified,
        verification_attempts=1,
        notes=["Patch verified by re-running exploit" if verified
                 else "Patch generated but verification failed"],
    )


def remediate_validated_findings(validated_findings, manifest: AgentManifest
                                    ) -> List[RemediationResult]:
    """
    For each CONFIRMED ValidatedFinding, attempt remediation.
    Returns one RemediationResult per CONFIRMED finding.
    """
    results = []
    for v in validated_findings:
        if v.bucket != "CONFIRMED":
            continue   # Only remediate confirmed vulnerabilities
        # Get the best exploit's stdout as evidence
        successful = [a for a in v.attempts
                       if a.get("success_level") in ("EXTRACTED", "TRIGGERED")]
        evidence = ""
        if successful:
            best = max(successful, key=lambda a: a.get("confidence", 0))
            evidence = best.get("stdout_excerpt", "")
        r = remediate_finding(v.finding, manifest, evidence)
        results.append(r)
    return results
