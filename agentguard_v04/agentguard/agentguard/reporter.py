# =============================================================================
# reporter.py — Report Generation
# =============================================================================
# Takes findings from the analyzer and produces structured reports:
#   - Markdown (human-readable, dissertation-ready)
#   - JSON (machine-readable, for evaluation pipeline)
# =============================================================================

import json
import datetime
import re
from pathlib import Path
from typing import List
from collections import Counter


def _mask_value(val: str) -> str:
    if len(val) <= 4:
        return "*" * len(val)
    return val[:1] + "*" * (len(val) - 2) + val[-1:]


def _redact_discovered_secrets(text: str) -> str:
    """
    Mask likely credential/secret values before they are written into a
    report file, so that a report proving AGT-007 (hardcoded secrets) does
    not itself become a second place the real secret is stored in plaintext.
    This mirrors established practice in security tooling (e.g. Strix's
    TelemetrySanitizer) of redacting sensitive values from any persisted
    output, not just the live terminal.

    Heuristic, not exhaustive: masks quoted or bare values assigned to
    common credential-shaped keys in the captured stdout. Errs toward
    over-redacting excerpt text rather than under-redacting a real secret,
    since the excerpt's job is to prove extraction happened, not to
    preserve the exact value.
    """
    if not text:
        return text

    def _sub_quoted(m: "re.Match") -> str:
        return m.group(1) + _mask_value(m.group(2)) + m.group(3)

    def _sub_bare(m: "re.Match") -> str:
        return m.group(1) + _mask_value(m.group(2))

    redacted = re.sub(
        r'(?i)((?:password|passwd|pwd|secret|token|api[_-]?key|credential)["\']?\s*[:=]\s*["\'])([^"\']{4,})(["\'])',
        _sub_quoted, text,
    )
    redacted = re.sub(
        r'(?i)((?:password|passwd|pwd|secret|token|api[_-]?key|credential)\s*[:=]\s*)([^\s,"\']{4,})',
        _sub_bare, redacted,
    )
    return redacted

from .analyzer import Finding
from .graph_builder import AttackPath, classify_all_tools
from .parser import AgentManifest


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}


def sort_findings(findings: List[Finding]) -> List[Finding]:
    """Sort by severity (critical first), then by confidence (high first)."""
    return sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), -f.confidence)
    )


def severity_counts(findings: List[Finding]) -> dict:
    return dict(Counter(f.severity for f in findings))


def write_json_report(findings: List[Finding],
                      manifest: AgentManifest,
                      paths:    List[AttackPath],
                      output_path: str):
    """Machine-readable JSON report — used by evaluation pipeline."""
    report = {
        "scan_metadata": {
            "tool":        "AgentGuard v0.1",
            "timestamp":   datetime.datetime.utcnow().isoformat(),
            "target_file": manifest.file_path,
            "framework":   manifest.framework,
            "model":       manifest.model,
            "tool_count":  len(manifest.tools),
        },
        "summary": {
            "total_findings":  len(findings),
            "static_findings": len([f for f in findings if f.source == "static"]),
            "gemini_findings": len([f for f in findings if f.source == "gemini"]),
            "severity_counts": severity_counts(findings),
            "attack_paths":    len(paths),
        },
        "static_analysis": [
            f.to_dict() for f in sort_findings(findings) if f.source == "static"
        ],
        "gemini_analysis": [
            f.to_dict() for f in sort_findings(findings) if f.source == "gemini"
        ],
        "findings":     [f.to_dict() for f in sort_findings(findings)],
        "attack_paths": [
            {
                "outcome":      p.outcome,
                "severity":     p.severity,
                "description":  p.description,
                "tools_used":   p.tools_used,
                "capabilities": sorted(list(p.capabilities)),
            }
            for p in paths
        ],
        "tool_capabilities": {
            name: sorted(list(caps))
            for name, caps in classify_all_tools(manifest).items()
        },
    }

    Path(output_path).write_text(json.dumps(report, indent=2))


def write_markdown_report(findings: List[Finding],
                          manifest: AgentManifest,
                          paths:    List[AttackPath],
                          output_path: str):
    """Human-readable Markdown report — pentest-style format."""
    findings = sort_findings(findings)
    sev_counts = severity_counts(findings)

    md = []
    md.append(f"# AgentGuard Security Assessment Report")
    md.append("")
    md.append(f"**Target:** `{manifest.file_path}`  ")
    md.append(f"**Framework:** {manifest.framework}  ")
    md.append(f"**Model:** {manifest.model or 'not detected'}  ")
    md.append(f"**Scan Date:** {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}  ")
    md.append(f"**Scanner Version:** AgentGuard v0.1")
    md.append("")
    md.append("---")
    md.append("")

    # ── Executive Summary ────────────────────────────────────────────────────
    md.append(f"## Executive Summary")
    md.append("")
    md.append(f"The scanner identified **{len(findings)} security findings** "
              f"across {len(manifest.tools)} tool(s) in the agent codebase.")
    md.append("")
    _static_n = len([f for f in findings if f.source == "static"])
    _gemini_n = len([f for f in findings if f.source == "gemini"])
    md.append(f"- **{_static_n}** from deterministic static analysis "
              f"(Section 1)")
    md.append(f"- **{_gemini_n}** from Gemini AI semantic analysis "
              f"(Section 2)")
    md.append("")
    if sev_counts:
        md.append("**Severity Breakdown:**")
        md.append("")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = sev_counts.get(sev, 0)
            if count > 0:
                md.append(f"- {SEVERITY_EMOJI[sev]} **{sev}:** {count}")
        md.append("")

    if paths:
        md.append(f"**{len(paths)} attack path(s)** were identified through "
                  f"capability graph analysis.")
        md.append("")

    md.append("---")
    md.append("")

    # ── Attack Paths ─────────────────────────────────────────────────────────
    if paths:
        md.append(f"## Attack Paths")
        md.append("")
        md.append("The following high-risk attack outcomes are achievable through "
                  "combinations of the agent's tools:")
        md.append("")
        for i, p in enumerate(paths, 1):
            md.append(f"### Attack Path {i}: {p.outcome.replace('_', ' ').title()}")
            md.append("")
            md.append(f"**Severity:** {SEVERITY_EMOJI.get(p.severity,'')} {p.severity}  ")
            md.append(f"**Capabilities required:** `{', '.join(sorted(p.capabilities))}`  ")
            md.append(f"**Tools providing capabilities:** `{', '.join(p.tools_used)}`")
            md.append("")
            md.append(f"{p.description}")
            md.append("")
        md.append("---")
        md.append("")

    # ── Findings, split into two sections by analysis source ─────────────────
    static_findings = [f for f in findings if f.source == "static"]
    gemini_findings = [f for f in findings if f.source == "gemini"]

    def _emit_finding(i, f, include_ai_fix=False):
        md.append(f"### Finding {i}: {f.vuln_id} — {f.vuln_name}")
        md.append("")
        md.append(f"**Severity:** {SEVERITY_EMOJI.get(f.severity,'')} {f.severity}  ")
        md.append(f"**Confidence:** {f.confidence:.0%} ({f.confidence_label})  ")
        md.append(f"**Location:** `{f.location}`")
        md.append("")
        md.append(f"**Description:**  ")
        md.append(f"{f.description}")
        md.append("")
        md.append(f"**Evidence:**")
        md.append("```")
        md.append(f.evidence)
        md.append("```")
        md.append("")
        md.append(f"**Impact:**  ")
        md.append(f"{f.impact}")
        md.append("")
        md.append(f"**Remediation:**  ")
        md.append(f"{f.remediation}")
        md.append("")
        if include_ai_fix and f.ai_fix:
            md.append(f"**AI-suggested fix:**")
            md.append("```python")
            md.append(f.ai_fix)
            md.append("```")
            md.append("")
        md.append("---")
        md.append("")

    # Section 1 — Static Analysis
    md.append("## Section 1 — Static Analysis")
    md.append("")
    md.append("Deterministic findings from AST and pattern-based detectors. These "
              "run without any API and are fully reproducible.")
    md.append("")
    if not static_findings:
        md.append("*No issues found by static analysis.*")
        md.append("")
    else:
        for i, f in enumerate(static_findings, 1):
            _emit_finding(i, f)

    # Section 2 — Gemini AI Analysis
    md.append("## Section 2 — Gemini AI Analysis")
    md.append("")
    md.append("Semantic findings from the LLM reasoning layer. For each issue the "
              "model states what is wrong, proposes a fix (with replacement code "
              "where applicable), and reports a confidence level. Treat these as "
              "expert review to verify, not as proven facts.")
    md.append("")
    if not gemini_findings:
        md.append("*No additional issues raised by the AI layer "
                  "(or the AI layer was disabled with `--no-llm`).*")
        md.append("")
    else:
        for i, f in enumerate(gemini_findings, 1):
            _emit_finding(i, f, include_ai_fix=True)

    # ── Tool Inventory ───────────────────────────────────────────────────────
    md.append(f"## Tool Inventory")
    md.append("")
    md.append("| Tool | Capabilities |")
    md.append("|------|--------------|")
    for name, caps in classify_all_tools(manifest).items():
        cap_str = ", ".join(sorted(caps)) if caps else "*(none classified)*"
        md.append(f"| `{name}` | {cap_str} |")
    md.append("")

    md.append("---")
    md.append("")
    md.append(f"*Report generated by AgentGuard v0.4.1 — MSc Cyber Security Research*")
    md.append("")

    Path(output_path).write_text("\n".join(md))


def write_validated_markdown_report(validated, manifest, paths, output_path):
    """
    Write a Markdown report for VALIDATED findings (with exploit evidence).
    Used after the self-validation loop.
    """
    from .validator import ValidatedFinding

    BUCKET_EMOJI = {"CONFIRMED": "✅", "SUSPECTED": "🟡", "DISMISSED": "❌"}
    BUCKET_ORDER = {"CONFIRMED": 0, "SUSPECTED": 1, "DISMISSED": 2}

    confirmed = [v for v in validated if v.bucket == "CONFIRMED"]
    suspected = [v for v in validated if v.bucket == "SUSPECTED"]
    dismissed = [v for v in validated if v.bucket == "DISMISSED"]

    md = []
    md.append(f"# AgentGuard Validated Security Report")
    md.append("")
    md.append(f"**Target:** `{manifest.file_path}`  ")
    md.append(f"**Framework:** {manifest.framework}  ")
    md.append(f"**Scan Date:** {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}  ")
    md.append(f"**Self-Validation:** ENABLED — every finding tested via sandboxed exploit")
    md.append("")
    md.append("---")
    md.append("")

    md.append(f"## Executive Summary")
    md.append("")
    md.append(f"AgentGuard analysed `{manifest.file_path}` and found **{len(validated)} "
                f"potential issues**. Each was validated by attempting a sandboxed "
                f"proof-of-concept exploit.")
    md.append("")
    md.append(f"**Validation Results:**")
    md.append("")
    md.append(f"- ✅ **CONFIRMED:** {len(confirmed)} (exploit fired in sandbox)")
    md.append(f"- 🟡 **SUSPECTED:** {len(suspected)} (manual review recommended)")
    md.append(f"- ❌ **DISMISSED:** {len(dismissed)} (could not reproduce — likely false positive)")
    md.append("")
    md.append("---")
    md.append("")

    # ── CONFIRMED findings — these are the gold ─────────────────────────────
    if confirmed:
        md.append(f"## ✅ CONFIRMED Vulnerabilities ({len(confirmed)})")
        md.append("")
        md.append("These vulnerabilities were proven by successful sandboxed exploitation. "
                    "Each finding includes the proof-of-concept that worked.")
        md.append("")
        for i, v in enumerate(confirmed, 1):
            f = v.finding
            md.append(f"### {i}. {f.vuln_id} — {f.vuln_name}")
            md.append("")
            md.append(f"**Severity:** 🔴 {f.severity}  ")
            _src_label = "Gemini AI Semantic Analysis" if getattr(f, "source", "static") == "gemini" else "Static Analysis"
            md.append(f"**Location:** `{f.location}`  ")
            md.append(f"**Detected by:** {_src_label}  ")
            md.append(f"**Validation Confidence:** {v.final_confidence:.0%}")
            md.append("")
            md.append(f"**Description**  ")
            md.append(f"{f.description}")
            md.append("")
            md.append(f"**Impact**  ")
            md.append(f"{f.impact}")
            md.append("")
            md.append(f"**Remediation**  ")
            md.append(f"{f.remediation}")
            md.append("")

            # Best successful attempt
            successful = [a for a in v.attempts
                            if a.get("success_level") in ("EXTRACTED", "TRIGGERED")]
            if successful:
                best = max(successful, key=lambda a: a.get("confidence", 0))
                md.append(f"**Proof-of-Concept Strategy**  ")
                md.append(f"{best['strategy']}")
                md.append("")
                md.append(f"**Sandbox Output (excerpt)**")
                md.append("```")
                md.append(_redact_discovered_secrets(best.get("stdout_excerpt", "")[:600]))
                md.append("```")
                md.append("")
                md.append(f"**Differential Test:** {'✅ passed' if best.get('benign_clean') else '⚠️ inconclusive'}  ")
                md.append(f"**Execution Time:** {best.get('elapsed_sec', 0)}s  ")
                _sandbox_used = "Docker (isolated container — no network, no host filesystem access beyond the explicit mount)" if best.get("used_docker") else "subprocess (resource-limited: CPU/memory/process caps only — no filesystem or network isolation)"
                md.append(f"**Sandbox:** {_sandbox_used}")
                md.append("")

            # AI-prover structured verdict — the AI wrote and ran its own exploit
            if getattr(v, "ai_verdict", ""):
                md.append(f"**AI Self-Validation Verdict:** {v.ai_verdict}")
                md.append("")
                if v.ai_hypothesis:
                    md.append(f"**AI Hypothesis** — {v.ai_hypothesis}")
                    md.append("")
                if v.ai_method:
                    md.append(f"**What the AI's exploit did** — {v.ai_method}")
                    md.append("")
                if v.ai_exploit_code:
                    md.append("**The exploit the AI wrote and executed:**")
                    md.append("```python")
                    md.append(v.ai_exploit_code[:1500])
                    md.append("```")
                    md.append("")
                if v.ai_fix:
                    md.append(f"**The fix (the switch that removes this vulnerability)** — {v.ai_fix}")
                    md.append("")
                if getattr(v, "ai_tokens_in", 0) or getattr(v, "ai_tokens_out", 0):
                    md.append(f"**AI-prover token usage for this finding:** "
                              f"in={v.ai_tokens_in}, out={v.ai_tokens_out}, "
                              f"thinking={getattr(v, 'ai_tokens_thinking', 0)}, "
                              f"total={v.ai_tokens_in + v.ai_tokens_out + getattr(v, 'ai_tokens_thinking', 0)}")
                    md.append("")
            md.append("---")
            md.append("")

    # ── SUSPECTED findings ───────────────────────────────────────────────────
    if suspected:
        md.append(f"## 🟡 SUSPECTED Vulnerabilities ({len(suspected)})")
        md.append("")
        md.append("These findings appear plausible based on static analysis but the "
                    "sandboxed exploit did not produce a definitive proof. Manual "
                    "review by a security engineer is recommended.")
        md.append("")
        for i, v in enumerate(suspected, 1):
            f = v.finding
            _src_label = "Gemini AI Semantic Analysis" if getattr(f, "source", "static") == "gemini" else "Static Analysis"
            md.append(f"### {i}. {f.vuln_id} — {f.vuln_name}")
            md.append("")
            md.append(f"**Severity:** {f.severity}  ")
            md.append(f"**Location:** `{f.location}`  ")
            md.append(f"**Detected by:** {_src_label}  ")
            md.append(f"**Confidence:** {v.final_confidence:.0%}")
            md.append("")
            md.append(f"{f.description}")
            md.append("")
            if v.attempts:
                md.append(f"**Exploit attempts:** {len(v.attempts)}  ")
                best = max(v.attempts, key=lambda a: a.get("confidence", 0))
                md.append(f"**Best result:** {best.get('success_level')} "
                            f"(confidence {best.get('confidence', 0):.2f})")
                md.append("")
            if getattr(v, "ai_verdict", ""):
                md.append(f"**AI Self-Validation Verdict:** {v.ai_verdict}")
                md.append("")
                if v.ai_hypothesis:
                    md.append(f"**AI Hypothesis** — {v.ai_hypothesis}")
                    md.append("")
                if v.ai_method:
                    md.append(f"**What the AI's exploit did** — {v.ai_method}")
                    md.append("")
                if v.ai_exploit_code:
                    md.append("**The exploit the AI wrote and executed:**")
                    md.append("```python")
                    md.append(v.ai_exploit_code[:1500])
                    md.append("```")
                    md.append("")
                if v.ai_fix:
                    md.append(f"**Proposed fix** — {v.ai_fix}")
                    md.append("")
                if getattr(v, "ai_tokens_in", 0) or getattr(v, "ai_tokens_out", 0):
                    md.append(f"**AI-prover token usage for this finding:** "
                              f"in={v.ai_tokens_in}, out={v.ai_tokens_out}, "
                              f"thinking={getattr(v, 'ai_tokens_thinking', 0)}, "
                              f"total={v.ai_tokens_in + v.ai_tokens_out + getattr(v, 'ai_tokens_thinking', 0)}")
                    md.append("")
            md.append("---")
            md.append("")

    # ── DISMISSED summary only ───────────────────────────────────────────────
    if dismissed:
        md.append(f"## ❌ DISMISSED Findings ({len(dismissed)})")
        md.append("")
        md.append("These findings could not be reproduced via sandbox testing and are "
                    "likely false positives. Listed for transparency.")
        md.append("")
        for v in dismissed:
            _src_tag = "Gemini AI" if getattr(v.finding, "source", "static") == "gemini" else "Static"
            md.append(f"- `{v.finding.vuln_id}` at `{v.finding.location}` "
                        f"[{_src_tag}] ({len(v.attempts)} exploit attempts, max confidence "
                        f"{max([a.get('confidence',0) for a in v.attempts] + [0]):.2f})")
        md.append("")

    # ── AI-prover total token usage across the whole report ──────────────────
    _total_in = sum(getattr(v, "ai_tokens_in", 0) for v in validated)
    _total_out = sum(getattr(v, "ai_tokens_out", 0) for v in validated)
    _total_thinking = sum(getattr(v, "ai_tokens_thinking", 0) for v in validated)
    if _total_in or _total_out:
        md.append("## AI-Prover Token Usage (this report)")
        md.append("")
        md.append(f"- Input tokens: **{_total_in}**")
        md.append(f"- Output tokens (visible answer): **{_total_out}**")
        md.append(f"- Thinking tokens (invisible reasoning): **{_total_thinking}**")
        md.append(f"- Total tokens consumed: **{_total_in + _total_out + _total_thinking}**")
        md.append("")

    md.append("---")
    md.append("")
    md.append(f"*Report generated by AgentGuard v0.2 — Self-Validating Static Analysis*")

    Path(output_path).write_text("\n".join(md))


def write_validated_json_report(validated, manifest, paths, output_path):
    """JSON version for evaluation pipeline."""
    confirmed = [v for v in validated if v.bucket == "CONFIRMED"]
    suspected = [v for v in validated if v.bucket == "SUSPECTED"]
    dismissed = [v for v in validated if v.bucket == "DISMISSED"]

    report = {
        "scan_metadata": {
            "tool":        "AgentGuard v0.2 (with self-validation)",
            "timestamp":   datetime.datetime.utcnow().isoformat(),
            "target_file": manifest.file_path,
            "framework":   manifest.framework,
            "self_validation": True,
        },
        "summary": {
            "total":      len(validated),
            "confirmed":  len(confirmed),
            "suspected":  len(suspected),
            "dismissed":  len(dismissed),
        },
        "validated_findings": [v.to_dict() for v in validated],
    }
    Path(output_path).write_text(json.dumps(report, indent=2, default=str))


def print_console_summary(findings: List[Finding],
                          manifest: AgentManifest,
                          paths:    List[AttackPath]):
    """Quick summary to stdout after a scan."""
    findings = sort_findings(findings)
    sev = severity_counts(findings)

    print(f"\n{'═'*60}")
    print(f"  AGENTGUARD SCAN RESULTS")
    print(f"{'═'*60}")
    print(f"  Target:    {manifest.file_path}")
    print(f"  Framework: {manifest.framework}")
    print(f"  Tools:     {len(manifest.tools)}")
    print(f"  Findings:  {len(findings)}")
    print()
    if findings:
        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if sev.get(s, 0):
                print(f"    {SEVERITY_EMOJI[s]} {s:<10} {sev[s]}")
    print()
    if paths:
        print(f"  ATTACK PATHS:")
        for p in paths:
            print(f"    [{p.severity}] {p.outcome}")
        print()

    # Print top 5 findings
    if findings:
        print(f"  TOP FINDINGS:")
        for f in findings[:5]:
            print(f"    {SEVERITY_EMOJI.get(f.severity, '')} [{f.vuln_id}] {f.vuln_name}")
            print(f"       └─ {f.location}")
        if len(findings) > 5:
            print(f"    ... and {len(findings) - 5} more (see full report)")
    print()
