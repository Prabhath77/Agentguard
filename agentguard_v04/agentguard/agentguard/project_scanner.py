# =============================================================================
# project_scanner.py — Whole-Project Scanning (folders, zips, single files)
# =============================================================================
# Real agent codebases are not single files. A client hands over a zip or a
# repository directory containing dozens of modules: tools defined in one file,
# the system prompt in another, orchestration in a third.
#
# This module extends AgentGuard from single-file analysis to project-level
# analysis, and adds a class of detection that is impossible on one file at a
# time:
#
#   CROSS-FILE CAPABILITY CHAINS
#   A read_customer_records() tool in tools/database.py is harmless.
#   A send_email() tool in tools/comms.py is harmless.
#   Together they form a data-exfiltration chain — and no single-file scanner
#   can see it, because neither file contains the vulnerability on its own.
#
# The public entry point is scan_target(), which accepts a .py file, a folder,
# or a .zip archive and returns a ProjectScanResult in every case. Single-file
# scanning is therefore just the degenerate case of project scanning, which
# keeps one code path for both.
# =============================================================================

import os
import sys
import json
import shutil
import zipfile
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple

from .parser import parse_agent, AgentManifest, ToolDef
from .analyzer import analyze, Finding
from .graph_builder import (
    classify_tool, classify_all_tools, find_attack_paths,
    AttackPath, ATTACK_OUTCOMES,
)
from .taxonomy import Severity

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import (
    PROJECT_IGNORE_DIRS, PROJECT_MAX_FILES, PROJECT_MAX_FILE_SIZE,
)


# ─── Result containers ───────────────────────────────────────────────────────

@dataclass
class FileScanResult:
    """Everything AgentGuard learned about one source file."""
    path:          str                       # path relative to the project root
    absolute_path: str
    manifest:      Optional[AgentManifest]
    findings:      List[Finding] = field(default_factory=list)
    parse_error:   Optional[str] = None

    @property
    def is_agent_file(self) -> bool:
        """True when the file actually defines agent surface area."""
        if self.manifest is None:
            return False
        return bool(self.manifest.tools) or bool(self.manifest.system_prompt)

    @property
    def tool_count(self) -> int:
        return len(self.manifest.tools) if self.manifest else 0


@dataclass
class ProjectScanResult:
    """Aggregate result across every file in a project."""
    root:             str
    target_kind:      str                    # "file" | "folder" | "zip"
    files:            List[FileScanResult] = field(default_factory=list)
    cross_file_findings: List[Finding]     = field(default_factory=list)
    attack_paths:     List[AttackPath]     = field(default_factory=list)
    tool_origin:      Dict[str, str]       = field(default_factory=dict)
    skipped:          List[str]            = field(default_factory=list)

    # ── Convenience accessors ────────────────────────────────────────────
    @property
    def agent_files(self) -> List[FileScanResult]:
        return [f for f in self.files if f.is_agent_file]

    @property
    def all_findings(self) -> List[Finding]:
        """Per-file findings plus the cross-file ones, deduplicated."""
        out: List[Finding] = []
        for f in self.files:
            out.extend(f.findings)
        out.extend(self.cross_file_findings)

        seen: Set[Tuple[str, str]] = set()
        unique: List[Finding] = []
        for finding in out:
            key = (finding.vuln_id, finding.location)
            if key not in seen:
                seen.add(key)
                unique.append(finding)
        return unique

    @property
    def total_tools(self) -> int:
        return sum(f.tool_count for f in self.files)

    @property
    def frameworks(self) -> Set[str]:
        return {
            f.manifest.framework
            for f in self.agent_files
            if f.manifest and f.manifest.framework
        }

    def merged_manifest(self) -> AgentManifest:
        """
        Fuse every file into one synthetic manifest so that existing
        single-manifest machinery (capability graph, attack paths, reporting)
        works unchanged at project scope.
        """
        tools: List[ToolDef] = []
        memory: List[str] = []
        imports: List[str] = []
        literals: List[str] = []
        system_prompt = None
        framework = "custom"
        model = None
        sources: List[str] = []

        for f in self.files:
            if f.manifest is None:
                continue
            tools.extend(f.manifest.tools)
            memory.extend(f.manifest.memory_uses)
            imports.extend(f.manifest.imports)
            literals.extend(f.manifest.raw_string_literals)
            sources.append(f.manifest.source_code)

            # First real system prompt found wins; first non-custom framework wins.
            if system_prompt is None and f.manifest.system_prompt:
                system_prompt = f.manifest.system_prompt
            if framework == "custom" and f.manifest.framework != "custom":
                framework = f.manifest.framework
            if model is None and f.manifest.model:
                model = f.manifest.model

        return AgentManifest(
            file_path           = self.root,
            source_code         = "\n".join(sources),
            framework           = framework,
            model               = model,
            system_prompt       = system_prompt,
            tools               = tools,
            memory_uses         = sorted(set(memory)),
            imports             = sorted(set(imports)),
            raw_string_literals = literals,
        )


# ─── Target resolution: file, folder, or zip ─────────────────────────────────

def _extract_zip(zip_path: Path) -> Tuple[Path, tempfile.TemporaryDirectory]:
    """
    Extract a zip to a temporary directory, guarding against path traversal
    (the 'zip slip' vulnerability — a malicious archive containing ../ entries
    that would write outside the extraction root).

    Returns the extraction root and the TemporaryDirectory handle, which the
    caller must keep alive for as long as the files are needed.
    """
    tmp = tempfile.TemporaryDirectory(prefix="agentguard_zip_")
    root = Path(tmp.name)

    with zipfile.ZipFile(zip_path) as zf:
        for member in zf.namelist():
            destination = (root / member).resolve()
            if not str(destination).startswith(str(root.resolve())):
                raise ValueError(
                    f"Refusing to extract '{member}' — path traversal in archive."
                )
        zf.extractall(root)

    # A zip commonly wraps everything in one top-level folder; descend into it
    # so reported paths are not prefixed with a redundant directory name.
    entries = [p for p in root.iterdir() if not p.name.startswith("__MACOSX")]
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0], tmp
    return root, tmp


def discover_python_files(root: Path) -> Tuple[List[Path], List[str]]:
    """
    Walk a project tree and return the Python files worth scanning, plus a
    list of human-readable reasons for anything skipped.
    """
    found: List[Path] = []
    skipped: List[str] = []

    for dirpath, dirnames, filenames in os.walk(root):
        # Prune ignored directories in place so os.walk does not descend.
        dirnames[:] = [d for d in dirnames if d not in PROJECT_IGNORE_DIRS]

        for name in sorted(filenames):
            if not name.endswith(".py"):
                continue

            path = Path(dirpath) / name
            try:
                size = path.stat().st_size
            except OSError as exc:
                skipped.append(f"{path.name}: unreadable ({exc})")
                continue

            if size > PROJECT_MAX_FILE_SIZE:
                skipped.append(f"{path.name}: {size:,} bytes exceeds size limit")
                continue

            found.append(path)

            if len(found) >= PROJECT_MAX_FILES:
                skipped.append(
                    f"file cap of {PROJECT_MAX_FILES} reached — "
                    f"remaining files not scanned"
                )
                return found, skipped

    return found, skipped


# ─── Cross-file capability chain detection ───────────────────────────────────

def detect_cross_file_chains(result: ProjectScanResult) -> List[Finding]:
    """
    The core project-level contribution.

    Classify every tool in the project by capability, then check whether the
    capability sets required for each known attack outcome are satisfied by
    tools that live in DIFFERENT files. Chains contained within one file are
    already caught by the single-file analyzer, so only genuinely cross-file
    chains are reported here — which keeps this from double-counting.
    """
    findings: List[Finding] = []

    # capability -> list of (tool_name, file_path)
    capability_map: Dict[str, List[Tuple[str, str]]] = {}

    for file_result in result.files:
        if not file_result.manifest:
            continue
        for tool in file_result.manifest.tools:
            for capability in classify_tool(tool):
                capability_map.setdefault(capability, []).append(
                    (tool.name, file_result.path)
                )

    for outcome_name, outcome in ATTACK_OUTCOMES.items():
        required: Set[str] = outcome["required"]

        # Every capability in the chain must exist somewhere in the project.
        if not required.issubset(capability_map.keys()):
            continue

        # A chain needs at least two distinct capabilities to be cross-file.
        if len(required) < 2:
            continue

        # Pick providers so the chain spans as many files as possible. For each
        # capability we prefer a providing tool from a file not yet used, so a
        # chain is only classified "single-file" when EVERY provider genuinely
        # shares one file. (Choosing the first provider blindly would miss a
        # cross-file chain whenever a same-file provider happened to sort first.)
        providers: List[Tuple[str, str, str]] = []   # (capability, tool, file)
        used_files: Set[str] = set()
        for capability in sorted(required):
            candidates = capability_map[capability]
            # Prefer a provider in a file we have not used yet.
            pick = next(
                ((t, f) for t, f in candidates if f not in used_files),
                candidates[0],
            )
            tool_name, file_path = pick
            providers.append((capability, tool_name, file_path))
            used_files.add(file_path)

        files_involved = {file_path for _, _, file_path in providers}

        # Only report when the chain genuinely spans more than one file.
        if len(files_involved) < 2:
            continue

        chain_desc = " + ".join(
            f"{tool} ({Path(file).name} :: {cap})"
            for cap, tool, file in providers
        )

        findings.append(Finding(
            vuln_id     = "AGT-004",
            vuln_name   = "Unsafe Tool Chaining (cross-file)",
            severity    = outcome["severity"],
            location    = f"PROJECT :: {' -> '.join(sorted(files_involved))}",
            description = (
                f"Cross-file capability chain enables {outcome_name.replace('_', ' ').lower()}. "
                f"{outcome['description']} No single file contains this vulnerability; "
                f"it emerges only when the project is assessed as a whole."
            ),
            evidence    = chain_desc,
            impact      = (
                f"An attacker who compromises the agent through prompt injection can "
                f"chain tools across {len(files_involved)} modules to achieve "
                f"{outcome_name.replace('_', ' ').lower()}."
            ),
            remediation = (
                "Introduce a capability policy at the orchestration layer that blocks "
                "this tool sequence, or require human approval before the second tool "
                "in the chain executes. Per-module review will not surface this issue."
            ),
            confidence  = 0.85,
            source      = "static",
        ))

    return findings


# ─── Main scanning entry point ───────────────────────────────────────────────

def scan_target(target: str,
                use_llm: bool = True,
                verbose: bool = False) -> Tuple[ProjectScanResult, Optional[object]]:
    """
    Scan a .py file, a folder, or a .zip archive.

    Returns (result, tmpdir_handle). When the target was a zip, tmpdir_handle
    must be kept alive by the caller until it is finished with the extracted
    files; it is None otherwise.
    """
    path = Path(target).expanduser()
    if not path.exists():
        raise FileNotFoundError(f"Target not found: {target}")

    tmp_handle = None

    # ── Resolve what we are scanning ──────────────────────────────────────
    if path.is_file() and path.suffix == ".zip":
        root, tmp_handle = _extract_zip(path)
        target_kind = "zip"
        display_root = str(path)
    elif path.is_file():
        root = path.parent
        target_kind = "file"
        display_root = str(path)
    else:
        root = path
        target_kind = "folder"
        display_root = str(path)

    # ── Collect the files to scan ─────────────────────────────────────────
    if target_kind == "file":
        py_files = [path]
        skipped: List[str] = []
    else:
        py_files, skipped = discover_python_files(root)

    result = ProjectScanResult(
        root        = display_root,
        target_kind = target_kind,
        skipped     = skipped,
    )

    if not py_files:
        return result, tmp_handle

    # ── Toggle the LLM layer for this run ─────────────────────────────────
    from . import analyzer as _analyzer_module
    original_llm_setting = _analyzer_module.ENABLE_LLM_ANALYSIS
    if not use_llm:
        _analyzer_module.ENABLE_LLM_ANALYSIS = False

    try:
        for index, py_file in enumerate(py_files, 1):
            try:
                relative = str(py_file.relative_to(root))
            except ValueError:
                relative = py_file.name

            if verbose:
                print(f"      [{index}/{len(py_files)}] {relative}")

            file_result = FileScanResult(
                path          = relative,
                absolute_path = str(py_file),
                manifest      = None,
            )

            # A syntax error in one module must never abort the whole scan.
            try:
                manifest = parse_agent(str(py_file))
                file_result.manifest = manifest
            except SyntaxError as exc:
                file_result.parse_error = f"syntax error line {exc.lineno}: {exc.msg}"
                result.files.append(file_result)
                continue
            except Exception as exc:  # noqa: BLE001
                file_result.parse_error = str(exc)
                result.files.append(file_result)
                continue

            # Record which file each tool came from, for cross-file reporting.
            for tool in manifest.tools:
                result.tool_origin.setdefault(tool.name, relative)

            # Analyse files that carry agent surface area, and any file at all
            # for secret leakage — credentials hide in config modules too.
            if file_result.is_agent_file or manifest.raw_string_literals:
                try:
                    findings = analyze(manifest)
                except Exception as exc:  # noqa: BLE001
                    findings = []
                    file_result.parse_error = f"analysis error: {exc}"

                # Rewrite absolute paths in locations to project-relative ones
                # so reports read cleanly regardless of where the zip landed.
                for finding in findings:
                    finding.location = finding.location.replace(
                        str(py_file), relative
                    ).replace(manifest.file_path, relative)

                file_result.findings = findings

            result.files.append(file_result)

    finally:
        _analyzer_module.ENABLE_LLM_ANALYSIS = original_llm_setting

    # ── Project-level analysis ────────────────────────────────────────────
    merged = result.merged_manifest()
    result.attack_paths = find_attack_paths(merged)

    if target_kind != "file":
        result.cross_file_findings = detect_cross_file_chains(result)

    return result, tmp_handle


# ─── Console reporting ───────────────────────────────────────────────────────

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_MARK  = {
    "CRITICAL": "[CRITICAL]", "HIGH": "[HIGH]", "MEDIUM": "[MEDIUM]",
    "LOW": "[LOW]", "INFO": "[INFO]",
}


def print_project_summary(result: ProjectScanResult) -> None:
    """Human-readable console summary of a project scan."""
    findings = sorted(
        result.all_findings,
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), -f.confidence),
    )

    print(f"\n{'=' * 66}")
    print(f"  AGENTGUARD PROJECT SCAN")
    print(f"{'=' * 66}")
    print(f"  Target:       {result.root}")
    print(f"  Type:         {result.target_kind}")
    print(f"  Files parsed: {len(result.files)}")
    print(f"  Agent files:  {len(result.agent_files)}")
    print(f"  Tools found:  {result.total_tools}")
    if result.frameworks:
        print(f"  Frameworks:   {', '.join(sorted(result.frameworks))}")
    print(f"  Findings:     {len(findings)}")

    # Severity breakdown
    counts: Dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    if counts:
        print()
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if counts.get(severity):
                print(f"    {SEVERITY_MARK[severity]:<12} {counts[severity]}")

    # Per-file breakdown, worst first
    files_with_findings = [f for f in result.files if f.findings]
    if files_with_findings:
        print(f"\n{'-' * 66}")
        print(f"  FINDINGS BY FILE")
        print(f"{'-' * 66}")
        for file_result in sorted(
            files_with_findings, key=lambda f: -len(f.findings)
        ):
            worst = min(
                (SEVERITY_ORDER.get(f.severity, 99) for f in file_result.findings),
                default=99,
            )
            worst_label = next(
                (k for k, v in SEVERITY_ORDER.items() if v == worst), "INFO"
            )
            print(f"    {file_result.path:<44} "
                  f"{len(file_result.findings):>3}  (worst: {worst_label})")

    # The headline project-level result
    if result.cross_file_findings:
        print(f"\n{'-' * 66}")
        print(f"  CROSS-FILE CHAINS  ({len(result.cross_file_findings)})")
        print(f"  Vulnerabilities invisible to single-file analysis")
        print(f"{'-' * 66}")
        for finding in result.cross_file_findings:
            print(f"    {SEVERITY_MARK.get(finding.severity, '')} {finding.description.split('.')[0]}.")
            print(f"      Chain: {finding.evidence}")

    # Parse failures are worth surfacing rather than hiding
    broken = [f for f in result.files if f.parse_error]
    if broken:
        print(f"\n  Files that could not be fully analysed ({len(broken)}):")
        for file_result in broken[:8]:
            print(f"    - {file_result.path}: {file_result.parse_error}")
        if len(broken) > 8:
            print(f"    ... and {len(broken) - 8} more")

    if result.skipped:
        print(f"\n  Skipped ({len(result.skipped)}):")
        for reason in result.skipped[:5]:
            print(f"    - {reason}")

    print()


# ─── Project report writers ──────────────────────────────────────────────────

def write_project_json_report(result: ProjectScanResult, output_path: str) -> None:
    """Machine-readable project report."""
    import datetime

    findings = result.all_findings
    counts: Dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1

    report = {
        "scan_metadata": {
            "tool":        "AgentGuard v0.4",
            "scan_mode":   "project",
            "timestamp":   datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "target":      result.root,
            "target_kind": result.target_kind,
            "frameworks":  sorted(result.frameworks),
        },
        "summary": {
            "files_scanned":       len(result.files),
            "agent_files":         len(result.agent_files),
            "tools_found":         result.total_tools,
            "total_findings":      len(findings),
            "static_findings":     len([f for f in findings if f.source == "static"]),
            "gemini_findings":     len([f for f in findings if f.source == "gemini"]),
            "cross_file_findings": len(result.cross_file_findings),
            "severity_counts":     counts,
            "attack_paths":        len(result.attack_paths),
        },
        "files": [
            {
                "path":          f.path,
                "is_agent_file": f.is_agent_file,
                "framework":     f.manifest.framework if f.manifest else None,
                "tools":         [t.name for t in f.manifest.tools] if f.manifest else [],
                "finding_count": len(f.findings),
                "findings":      [x.to_dict() for x in f.findings],
                "parse_error":   f.parse_error,
            }
            for f in result.files
        ],
        "cross_file_findings": [f.to_dict() for f in result.cross_file_findings],
        "attack_paths": [
            {
                "outcome":      p.outcome,
                "severity":     p.severity,
                "description":  p.description,
                "tools_used":   p.tools_used,
                "capabilities": sorted(list(p.capabilities)),
            }
            for p in result.attack_paths
        ],
        "tool_origin": result.tool_origin,
        "skipped":     result.skipped,
    }

    Path(output_path).write_text(json.dumps(report, indent=2))


def write_project_markdown_report(result: ProjectScanResult, output_path: str) -> None:
    """Human-readable project report in pentest style."""
    import datetime

    findings = sorted(
        result.all_findings,
        key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), -f.confidence),
    )
    counts: Dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1

    md: List[str] = []
    md.append("# AgentGuard Project Security Assessment")
    md.append("")
    md.append(f"**Target:** `{result.root}`  ")
    md.append(f"**Scan mode:** whole-project ({result.target_kind})  ")
    md.append(f"**Files scanned:** {len(result.files)}  ")
    md.append(f"**Agent files:** {len(result.agent_files)}  ")
    md.append(f"**Tools discovered:** {result.total_tools}  ")
    if result.frameworks:
        md.append(f"**Frameworks:** {', '.join(sorted(result.frameworks))}  ")
    md.append(f"**Scan date:** "
              f"{datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  ")
    md.append("**Scanner:** AgentGuard v0.4")
    md.append("")
    md.append("---")
    md.append("")

    # ── Executive summary ────────────────────────────────────────────────
    md.append("## Executive Summary")
    md.append("")
    md.append(f"AgentGuard assessed **{len(result.files)} source file(s)** and identified "
              f"**{len(findings)} security finding(s)** across "
              f"**{result.total_tools} tool(s)**.")
    md.append("")
    if counts:
        md.append("| Severity | Count |")
        md.append("|----------|-------|")
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if counts.get(severity):
                md.append(f"| {severity} | {counts[severity]} |")
        md.append("")

    if result.cross_file_findings:
        md.append(f"Critically, **{len(result.cross_file_findings)} vulnerability chain(s) "
                  f"span multiple files** and would not be detected by any scanner "
                  f"operating on one file at a time.")
        md.append("")

    md.append("---")
    md.append("")

    # ── Cross-file chains, first because they are the differentiator ─────
    if result.cross_file_findings:
        md.append("## Cross-File Capability Chains")
        md.append("")
        md.append("These vulnerabilities emerge only when the project is assessed as a "
                  "whole. Each individual module is safe in isolation; the risk is "
                  "created by the combination of capabilities they collectively expose "
                  "to the agent.")
        md.append("")
        for index, finding in enumerate(result.cross_file_findings, 1):
            md.append(f"### Chain {index}: {finding.vuln_id} — {finding.vuln_name}")
            md.append("")
            md.append(f"**Severity:** {finding.severity}  ")
            md.append(f"**Confidence:** {finding.confidence:.0%}  ")
            md.append(f"**Files involved:** `{finding.location}`")
            md.append("")
            md.append(f"{finding.description}")
            md.append("")
            md.append("**Chain composition:**")
            md.append("```")
            md.append(finding.evidence)
            md.append("```")
            md.append("")
            md.append(f"**Impact:** {finding.impact}")
            md.append("")
            md.append(f"**Remediation:** {finding.remediation}")
            md.append("")
            md.append("---")
            md.append("")

    # ── File inventory ───────────────────────────────────────────────────
    md.append("## File Inventory")
    md.append("")
    md.append("| File | Agent file | Framework | Tools | Findings |")
    md.append("|------|-----------|-----------|-------|----------|")
    for file_result in result.files:
        framework = file_result.manifest.framework if file_result.manifest else "—"
        md.append(
            f"| `{file_result.path}` "
            f"| {'yes' if file_result.is_agent_file else 'no'} "
            f"| {framework} "
            f"| {file_result.tool_count} "
            f"| {len(file_result.findings)} |"
        )
    md.append("")
    md.append("---")
    md.append("")

    # ── Per-file findings ────────────────────────────────────────────────
    md.append("## Findings by File")
    md.append("")
    files_with_findings = [f for f in result.files if f.findings]
    if not files_with_findings:
        md.append("*No per-file vulnerabilities detected.*")
        md.append("")
    else:
        for file_result in files_with_findings:
            md.append(f"### `{file_result.path}`")
            md.append("")

            file_static = [f for f in file_result.findings if f.source == "static"]
            file_gemini = [f for f in file_result.findings if f.source == "gemini"]

            def _emit_project_finding(finding, include_ai_fix=False):
                md.append(f"#### {finding.vuln_id} — {finding.vuln_name}")
                md.append("")
                md.append(f"**Severity:** {finding.severity}  ")
                label = getattr(finding, "confidence_label", "")
                md.append(f"**Confidence:** {finding.confidence:.0%}"
                          f"{f' ({label})' if label else ''}  ")
                md.append(f"**Location:** `{finding.location}`")
                md.append("")
                md.append(f"{finding.description}")
                md.append("")
                md.append("**Evidence:**")
                md.append("```")
                md.append(finding.evidence)
                md.append("```")
                md.append("")
                md.append(f"**Impact:** {finding.impact}")
                md.append("")
                md.append(f"**Remediation:** {finding.remediation}")
                md.append("")
                if include_ai_fix and getattr(finding, "ai_fix", ""):
                    md.append("**AI-suggested fix:**")
                    md.append("```python")
                    md.append(finding.ai_fix)
                    md.append("```")
                    md.append("")

            md.append("**Static analysis:**")
            md.append("")
            if file_static:
                for finding in sorted(file_static, key=lambda f: SEVERITY_ORDER.get(f.severity, 99)):
                    _emit_project_finding(finding)
            else:
                md.append("*No static findings in this file.*")
                md.append("")

            md.append("**Gemini AI analysis:**")
            md.append("")
            if file_gemini:
                for finding in sorted(file_gemini, key=lambda f: SEVERITY_ORDER.get(f.severity, 99)):
                    _emit_project_finding(finding, include_ai_fix=True)
            else:
                md.append("*No AI findings in this file "
                          "(or AI layer disabled with `--no-llm`).*")
                md.append("")

            md.append("---")
            md.append("")

    # ── Attack paths ─────────────────────────────────────────────────────
    if result.attack_paths:
        md.append("## Project-Wide Attack Paths")
        md.append("")
        for path in result.attack_paths:
            md.append(f"- **{path.outcome.replace('_', ' ').title()}** "
                      f"({path.severity}) — {path.description} "
                      f"Tools: `{', '.join(path.tools_used)}`")
        md.append("")

    md.append("---")
    md.append("")
    md.append("*Report generated by AgentGuard v0.4 — MSc Cyber Security Research*")
    md.append("")

    Path(output_path).write_text("\n".join(md))
