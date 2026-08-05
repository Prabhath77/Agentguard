# =============================================================================
# main.py — AgentGuard CLI
# =============================================================================
# Usage:
#   python -m agentguard.main scan <agent_file.py>
#   python -m agentguard.main scan <agent_file.py> --no-llm     # Static only
#   python -m agentguard.main evaluate                          # Run benchmark
#   python -m agentguard.main taxonomy                          # Print Top 10
# =============================================================================

import sys
import json
import argparse
from pathlib import Path
from typing import Dict

from .parser        import parse_agent
from .analyzer      import analyze, Finding
from .graph_builder import find_attack_paths, print_capability_summary, print_attack_paths
from .reporter      import write_json_report, write_markdown_report, print_console_summary
from .taxonomy      import AGENT_TOP_10
from .project_scanner import (
    scan_target, print_project_summary,
    write_project_json_report, write_project_markdown_report,
)
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import REPORT_DIR, LLM_PROVIDER, LLM_MODEL


# ─── Target-type helpers ─────────────────────────────────────────────────────

def classify_target(target: str) -> str:
    """Return 'file', 'folder', or 'zip' for a scan target."""
    path = Path(target).expanduser()
    if path.is_dir():
        return "folder"
    if path.suffix == ".zip":
        return "zip"
    return "file"


# ─── Commands ────────────────────────────────────────────────────────────────

def cmd_validate_full(args):
    """Full v0.3 pipeline: scan + validate + remediate + verify patches."""
    target = Path(args.target)
    if not target.exists():
        print(f"[ERROR] File not found: {target}")
        sys.exit(1)

    from .validator      import validate_findings, print_validation_summary
    from .remediation    import remediate_validated_findings
    from .reporter       import (
        write_validated_markdown_report, write_validated_json_report
    )
    from .cost_monitor   import (
        reset_cost_tracker, get_cost_report, print_cost_summary
    )
    from .reasoning_log  import reset_reasoning_log, get_reasoning_log

    # Reset cost & reasoning trackers for this scan
    reset_cost_tracker()
    reset_reasoning_log()

    print(f"\n[1/6] Parsing {target}...")
    manifest = parse_agent(str(target))
    print(f"      Found {len(manifest.tools)} tool(s), framework: {manifest.framework}")

    print(f"\n[2/6] Building capability graph...")
    paths = find_attack_paths(manifest)
    print(f"      Identified {len(paths)} potential attack path(s)")

    print(f"\n[3/6] Running static + LLM analysis...")
    if args.no_llm:
        from . import analyzer as _a
        _a.ENABLE_LLM_ANALYSIS = False
    findings = analyze(manifest)
    print(f"      Identified {len(findings)} candidate finding(s)")

    print(f"\n[4/6] Self-validation loop (Phase 3 + Phase 4)...")
    validated = validate_findings(
        findings, manifest,
        use_llm_fallback = not args.no_llm,
        run_benign       = not args.no_benign,
        verbose          = True,
    )

    print(f"\n[5/6] Semantic remediation — generating verified patches...")
    confirmed_count = sum(1 for v in validated if v.bucket == "CONFIRMED")
    if confirmed_count == 0 or args.no_remediation:
        print(f"      Skipped (no confirmed findings or --no-remediation set)")
        remediations = []
    else:
        remediations = remediate_validated_findings(validated, manifest)
        verified_count = sum(1 for r in remediations if r.verified)
        print(f"      Generated {len(remediations)} patches, {verified_count} verified")

    print(f"\n[6/6] Writing reports...")
    Path(REPORT_DIR).mkdir(exist_ok=True)
    base = target.stem
    md_path   = Path(REPORT_DIR) / f"{base}_v03_report.md"
    json_path = Path(REPORT_DIR) / f"{base}_v03_report.json"

    write_v03_markdown_report(validated, remediations, manifest, paths,
                                str(md_path))
    write_v03_json_report(validated, remediations, manifest, paths,
                            str(json_path))
    print(f"      Markdown: {md_path}")
    print(f"      JSON:     {json_path}")

    print_validation_summary(validated)
    print_cost_summary()


def write_v03_markdown_report(validated, remediations, manifest, paths, output_path):
    """v0.3 report with remediation + reasoning."""
    from .reporter      import write_validated_markdown_report
    from .reasoning_log import get_reasoning_log
    from .cost_monitor  import get_cost_report

    # Start with the standard validated report
    write_validated_markdown_report(validated, manifest, paths, output_path)

    # Append remediation + reasoning sections
    lines = []
    lines.append("\n\n---\n\n## 🛠 Verified Patches\n")
    if not remediations:
        lines.append("*No remediations were generated.*\n")
    else:
        for i, r in enumerate(remediations, 1):
            verified_badge = "✅ VERIFIED" if r.verified else "⚠️ UNVERIFIED"
            lines.append(f"### Patch {i}: {r.finding.vuln_id} {verified_badge}\n")
            lines.append(f"**Location:** `{r.finding.location}`  ")
            if r.patch:
                lines.append(f"**Change:** {r.patch.diff_summary}  ")
                lines.append(f"**Rationale:** {r.patch.rationale}\n")
                lines.append("**Original (vulnerable):**\n")
                lines.append("```python")
                lines.append(r.patch.original_code[:1200])
                lines.append("```\n")
                lines.append("**Patched:**\n")
                lines.append("```python")
                lines.append(r.patch.patched_code[:1200])
                lines.append("```\n")
                if r.verified:
                    lines.append("> ✓ Re-running the exploit against the patched "
                                  "code did NOT succeed. The patch is verified to "
                                  "close the vulnerability.\n")
                else:
                    lines.append("> ⚠ Patch was generated but verification was "
                                  "inconclusive. Manual review recommended.\n")
            lines.append("\n---\n")

    lines.append("\n## 🧠 Reasoning Log\n")
    log = get_reasoning_log()
    if not log.steps:
        lines.append("*(no reasoning steps recorded)*")
    else:
        lines.append(f"AgentGuard recorded {len(log.steps)} reasoning steps during this scan.\n")
        lines.append("```")
        for i, s in enumerate(log.steps, 1):
            attempt = f" [attempt {s.attempt_num}]" if s.attempt_num else ""
            lines.append(f"{i}. [{s.step_type}]{attempt} {s.summary}")
            if s.detail:
                for dl in s.detail.split("\n")[:3]:
                    if dl.strip():
                        lines.append(f"     {dl.strip()[:120]}")
        lines.append("```")

    lines.append("\n## 💰 Cost Report\n")
    cr = get_cost_report()
    lines.append(f"- LLM calls: **{cr.total_calls}**  ")
    lines.append(f"- Input tokens: **{cr.total_input_tokens:,}**  ")
    lines.append(f"- Output tokens: **{cr.total_output_tokens:,}**  ")
    lines.append(f"- Estimated cost: **${cr.total_cost_usd:.4f}**  ")
    if cr.pruned_tokens_saved > 0:
        pct = 100 * cr.pruned_tokens_saved / (cr.total_input_tokens + cr.pruned_tokens_saved)
        lines.append(f"- Tokens saved by context pruning: **{cr.pruned_tokens_saved:,} ({pct:.1f}%)**")
    lines.append(f"- Cache hits: **{cr.cache_hits}**\n")

    # Append to the existing file
    with open(output_path, "a") as f:
        f.write("\n".join(lines))


def write_v03_json_report(validated, remediations, manifest, paths, output_path):
    from .reasoning_log import get_reasoning_log
    from .cost_monitor  import get_cost_report
    import datetime

    report = {
        "scan_metadata": {
            "tool":      "AgentGuard v0.3",
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "target_file": manifest.file_path,
            "framework":   manifest.framework,
        },
        "summary": {
            "total":     len(validated),
            "confirmed": sum(1 for v in validated if v.bucket == "CONFIRMED"),
            "suspected": sum(1 for v in validated if v.bucket == "SUSPECTED"),
            "dismissed": sum(1 for v in validated if v.bucket == "DISMISSED"),
            "patches_generated": len(remediations),
            "patches_verified":  sum(1 for r in remediations if r.verified),
        },
        "validated_findings": [v.to_dict() for v in validated],
        "remediations":       [r.to_dict() for r in remediations],
        "reasoning_log":      get_reasoning_log().to_dict(),
        "cost_report":        get_cost_report().to_dict(),
    }
    Path(output_path).write_text(json.dumps(report, indent=2, default=str))


def cmd_validate(args):
    """Scan + run self-validation loop with sandboxed exploits."""
    target = Path(args.target)
    if not target.exists():
        print(f"[ERROR] Target not found: {target}")
        sys.exit(1)

    if classify_target(args.target) in ("folder", "zip"):
        return cmd_validate_project(args)

    from .validator import (
        validate_findings, print_validation_summary
    )
    from .reporter import (
        write_validated_markdown_report, write_validated_json_report
    )

    print(f"\n[1/5] Parsing {target}...")
    manifest = parse_agent(str(target))
    print(f"      Found {len(manifest.tools)} tool(s), framework: {manifest.framework}")

    print(f"\n[2/5] Building capability graph...")
    paths = find_attack_paths(manifest)
    print(f"      Identified {len(paths)} potential attack path(s)")

    print(f"\n[3/5] Running static + LLM analysis...")
    if args.no_llm:
        from . import analyzer as _a
        _a.ENABLE_LLM_ANALYSIS = False
    findings = analyze(manifest)
    print(f"      Identified {len(findings)} candidate finding(s)")

    print(f"\n[4/5] Self-validation loop (Phase 3 + Phase 4)...")
    validated = validate_findings(
        findings, manifest,
        use_llm_fallback = not args.no_llm,
        run_benign       = not args.no_benign,
        ai_prover_first  = getattr(args, "ai_prover_first", False),
        verbose          = True,
    )

    print(f"\n[5/5] Writing reports...")
    Path(REPORT_DIR).mkdir(exist_ok=True)
    base = target.stem
    md_path   = Path(REPORT_DIR) / f"{base}_validated_report.md"
    json_path = Path(REPORT_DIR) / f"{base}_validated_report.json"
    write_validated_markdown_report(validated, manifest, paths, str(md_path))
    write_validated_json_report(validated, manifest, paths, str(json_path))
    print(f"      Markdown: {md_path}")
    print(f"      JSON:     {json_path}")

    print_validation_summary(validated)


def cmd_validate_project(args):
    """
    Run the full validate pipeline across every agent file in a project.

    Each agent file gets its own sandboxed exploit validation; cross-file
    chains are reported alongside as static findings, since proving a chain
    end-to-end would require instantiating the whole application.
    """
    from .validator import validate_findings

    kind = classify_target(args.target)
    print(f"\n[1/3] Resolving {kind}: {args.target}")

    result, tmp_handle = scan_target(
        args.target,
        use_llm = not args.no_llm,
        verbose = False,
    )

    try:
        agent_files = result.agent_files
        print(f"      {len(result.files)} file(s), "
              f"{len(agent_files)} containing agent code")

        if not agent_files:
            print("\n[!] No agent code found in this project — nothing to validate.")
            print_project_summary(result)
            return

        print(f"\n[2/3] Validating findings via sandboxed exploits...")

        totals = {"CONFIRMED": 0, "SUSPECTED": 0, "DISMISSED": 0}
        per_file_validated = {}

        for index, file_result in enumerate(agent_files, 1):
            if not file_result.findings:
                continue
            print(f"\n  ({index}/{len(agent_files)}) {file_result.path}")
            validated = validate_findings(
                file_result.findings,
                file_result.manifest,
                use_llm_fallback = not args.no_llm,
                run_benign       = not args.no_benign,
            )
            per_file_validated[file_result.path] = validated
            for item in validated:
                bucket = getattr(item, "bucket", None) or getattr(item, "status", "")
                if bucket in totals:
                    totals[bucket] += 1

        print(f"\n[3/3] Writing reports...")
        Path(REPORT_DIR).mkdir(exist_ok=True)
        base = Path(args.target).stem or "project"
        json_path = Path(REPORT_DIR) / f"{base}_project_report.json"
        md_path   = Path(REPORT_DIR) / f"{base}_project_report.md"
        write_project_json_report(result, str(json_path))
        write_project_markdown_report(result, str(md_path))
        print(f"      JSON:     {json_path}")
        print(f"      Markdown: {md_path}")

        print_project_summary(result)

        print(f"{'=' * 66}")
        print(f"  PROJECT VALIDATION TOTALS")
        print(f"{'=' * 66}")
        print(f"    CONFIRMED:  {totals['CONFIRMED']}")
        print(f"    SUSPECTED:  {totals['SUSPECTED']}")
        print(f"    DISMISSED:  {totals['DISMISSED']}")
        if result.cross_file_findings:
            print(f"    CROSS-FILE: {len(result.cross_file_findings)} "
                  f"(static; span multiple modules)")
        print()

    finally:
        if tmp_handle is not None:
            tmp_handle.cleanup()


def cmd_providers(args):
    """Show the active LLM backend and optionally test connectivity."""
    from ._llm_backend import provider_banner, key_is_configured, chat

    print(f"\n{'=' * 66}")
    print(f"  AGENTGUARD LLM BACKEND")
    print(f"{'=' * 66}")
    print(f"  Active provider: {LLM_PROVIDER}")
    print(f"  Active model:    {LLM_MODEL}")
    print(f"  Key status:      "
          f"{'configured' if key_is_configured() else 'NOT SET'}")
    print()
    print(f"  Free providers (no credit card required):")
    print(f"    gemini  Google AI Studio   https://aistudio.google.com/apikey")
    print(f"            export GEMINI_API_KEY=\"AIza...\"")
    print(f"    groq    Groq Cloud         https://console.groq.com/keys")
    print(f"            export GROQ_API_KEY=\"gsk_...\"")
    print()
    print(f"  Force a provider:  export AGENTGUARD_PROVIDER=groq")
    print(f"  Run without any:   add --no-llm to scan / validate / evaluate")
    print()

    if args.test:
        if not key_is_configured():
            print("  [!] Cannot test — no API key set for this provider.\n")
            sys.exit(1)
        print("  Testing connectivity...")
        try:
            result = chat("Reply with exactly the word: OK")
            print(f"  [OK] {LLM_PROVIDER} responded: {result.text.strip()[:40]!r}")
            print(f"       tokens in={result.input_tokens} "
                  f"out={result.output_tokens}\n")
        except Exception as exc:  # noqa: BLE001
            print(f"  [FAIL] {exc}\n")
            sys.exit(1)


def cmd_scan_project(args):
    """
    Scan a whole project: a folder or a .zip archive.

    This is the mode used for real client engagements, where the deliverable
    is an entire codebase rather than one file. It additionally detects
    capability chains that span multiple modules, which single-file analysis
    cannot see by construction.
    """
    kind = classify_target(args.target)
    print(f"\n[1/4] Resolving {kind}: {args.target}")

    result, tmp_handle = scan_target(
        args.target,
        use_llm = not args.no_llm,
        verbose = args.verbose,
    )

    try:
        print(f"      Discovered {len(result.files)} Python file(s), "
              f"{len(result.agent_files)} containing agent code")

        print(f"\n[2/4] Analysing {len(result.files)} file(s)"
              f"{' (static only)' if args.no_llm else ''}...")
        print(f"      {result.total_tools} tool(s) across the project")

        print(f"\n[3/4] Cross-file capability chain analysis...")
        print(f"      {len(result.cross_file_findings)} cross-file chain(s), "
              f"{len(result.attack_paths)} project-wide attack path(s)")

        print(f"\n[4/4] Writing reports...")
        Path(REPORT_DIR).mkdir(exist_ok=True)
        base = Path(args.target).stem or "project"
        json_path = Path(REPORT_DIR) / f"{base}_project_report.json"
        md_path   = Path(REPORT_DIR) / f"{base}_project_report.md"
        write_project_json_report(result, str(json_path))
        write_project_markdown_report(result, str(md_path))
        print(f"      JSON:     {json_path}")
        print(f"      Markdown: {md_path}")

        print_project_summary(result)

    finally:
        # Release the temp directory holding an extracted zip.
        if tmp_handle is not None:
            tmp_handle.cleanup()


def cmd_scan_repeat(args):
    """
    Scan the SAME file/folder/zip N times and report whether the findings are
    identical every time.

    Unlike `full-eval` and `determinism` (which run the built-in benchmark and
    need ground truth to compute precision/recall), this works on ANY target
    you point it at, because it measures only consistency — same vuln IDs, same
    locations, same severities across runs — not correctness. Use it on real
    projects where you have no ground truth.
    """
    import time as _time
    import json as _json
    target = Path(args.target)
    if not target.exists():
        print(f"[ERROR] Target not found: {target}")
        sys.exit(1)

    n_runs = args.runs
    kind = classify_target(args.target)
    print(f"\n{'=' * 66}")
    print(f"  REPEATED SCAN — {n_runs} runs of a {kind}")
    print(f"  Target: {args.target}")
    print(f"  LLM: {'ON' if args.with_llm else 'OFF (static, deterministic)'}")
    print(f"{'=' * 66}")

    signatures = []
    per_run_counts = []
    per_run_times = []

    for i in range(1, n_runs + 1):
        t0 = _time.perf_counter()
        result, tmp_handle = scan_target(
            args.target, use_llm=args.with_llm, verbose=False
        )
        elapsed = _time.perf_counter() - t0
        try:
            findings = result.all_findings
            # A stable signature of this run: sorted (location, id, severity).
            sig = sorted(
                f"{f.location}|{f.vuln_id}|{f.severity}" for f in findings
            )
            signatures.append("\n".join(sig))
            per_run_counts.append(len(findings))
            per_run_times.append(elapsed)
            print(f"  Run {i}/{n_runs}: {len(findings)} finding(s) in {elapsed:.2f}s")
        finally:
            if tmp_handle is not None:
                tmp_handle.cleanup()

    unique = len(set(signatures))
    print(f"\n{'-' * 66}")
    print(f"  Unique outcomes across {n_runs} runs: {unique}")
    if unique == 1:
        print(f"  Result: DETERMINISTIC — identical findings every run.")
    else:
        print(f"  Result: NON-DETERMINISTIC — {unique} different outcomes.")
        print(f"  (Expected if --with-llm is set; the AI layer can vary.)")
    print(f"  Finding counts per run: {per_run_counts}")
    print(f"  Median scan time: {sorted(per_run_times)[len(per_run_times)//2]:.2f}s")
    print()

    Path(REPORT_DIR).mkdir(exist_ok=True)
    out = Path(REPORT_DIR) / f"repeat_scan_{target.stem or 'target'}.json"
    out.write_text(_json.dumps({
        "target": args.target,
        "kind": kind,
        "runs": n_runs,
        "llm_enabled": args.with_llm,
        "unique_outcomes": unique,
        "deterministic": unique == 1,
        "finding_counts_per_run": per_run_counts,
        "scan_times_s": [round(t, 3) for t in per_run_times],
    }, indent=2))
    print(f"  Report: {out}\n")


def cmd_scan(args):
    """Scan a single file, a folder, or a zip archive."""
    target = Path(args.target)
    if not target.exists():
        print(f"[ERROR] Target not found: {target}")
        sys.exit(1)

    # Folders and zips take the project path; single .py files keep the
    # original single-file flow so existing behaviour is unchanged.
    if classify_target(args.target) in ("folder", "zip"):
        return cmd_scan_project(args)

    print(f"\n[1/4] Parsing {target}...")
    manifest = parse_agent(str(target))
    print(f"      Found {len(manifest.tools)} tool(s), framework: {manifest.framework}")

    print(f"\n[2/4] Building capability graph...")
    paths = find_attack_paths(manifest)
    print(f"      Identified {len(paths)} potential attack path(s)")

    print(f"\n[3/4] Running vulnerability analysis...")
    if args.no_llm:
        # Patch: disable LLM for this run
        from . import analyzer as _a
        _a.ENABLE_LLM_ANALYSIS = False
    findings = analyze(manifest)
    print(f"      Identified {len(findings)} finding(s)")

    print(f"\n[4/4] Writing reports...")
    Path(REPORT_DIR).mkdir(exist_ok=True)
    base = target.stem
    json_path = Path(REPORT_DIR) / f"{base}_report.json"
    md_path   = Path(REPORT_DIR) / f"{base}_report.md"
    write_json_report(findings, manifest, paths, str(json_path))
    write_markdown_report(findings, manifest, paths, str(md_path))
    print(f"      JSON:     {json_path}")
    print(f"      Markdown: {md_path}")

    if args.verbose:
        print_capability_summary(manifest)
        print_attack_paths(paths)
    print_console_summary(findings, manifest, paths)


def cmd_evaluate_projects(args):
    """
    Evaluate the multi-file project benchmark.

    Scored on two axes that the single-file benchmark cannot measure:
      1. Did the scanner find the expected vulnerability classes in a project
         whose files are individually unremarkable?
      2. Did it detect the cross-file capability chains, which are invisible
         to any scanner that analyses one file at a time?
    """
    projects_dir   = Path("benchmark_projects")
    ground_truth_f = projects_dir / "project_ground_truth.json"

    if not ground_truth_f.exists():
        print(f"[ERROR] Project ground truth not found: {ground_truth_f}")
        sys.exit(1)

    ground_truth: Dict = json.loads(ground_truth_f.read_text())

    print(f"\n{'=' * 66}")
    print(f"  AGENTGUARD PROJECT BENCHMARK")
    print(f"  {len(ground_truth)} multi-file agent projects")
    print(f"{'=' * 66}")

    total_tp = total_fp = total_fn = 0
    chain_hits = chain_expected = 0
    clean_pass = clean_total = 0
    rows = []

    for project_name in sorted(ground_truth.keys()):
        spec = ground_truth[project_name]
        project_path = projects_dir / project_name
        if not project_path.exists():
            print(f"\n  [SKIP] {project_name} — folder not found")
            continue

        print(f"\n  Scanning project: {project_name}")

        result, tmp_handle = scan_target(
            str(project_path),
            use_llm = args.with_llm,
            verbose = False,
        )
        try:
            # Per-file findings and cross-file chains are scored on separate
            # axes. Cross-file chains are reported under AGT-004, so counting
            # them here as well would penalise the same detection twice — once
            # as a per-file false positive and once in the chain score.
            per_file_findings = [f for file_result in result.files
                                 for f in file_result.findings]
            found_ids = {f.vuln_id for f in per_file_findings}
            expected_ids = set(spec.get("expected_findings", []))

            tp = len(found_ids & expected_ids)
            fp = len(found_ids - expected_ids)
            fn = len(expected_ids - found_ids)
            total_tp, total_fp, total_fn = total_tp + tp, total_fp + fp, total_fn + fn

            # Cross-file chain scoring
            expected_chains = spec.get("expected_cross_file", [])
            found_chain_text = " ".join(
                f.description.upper() for f in result.cross_file_findings
            )
            hit = 0
            for chain in expected_chains:
                if chain.replace("_", " ").upper() in found_chain_text:
                    hit += 1
            chain_hits += hit
            chain_expected += len(expected_chains)

            # Negative-control scoring
            if spec.get("should_be_clean"):
                clean_total += 1
                if not result.all_findings:
                    clean_pass += 1

            print(f"    Files:     {len(result.files)} "
                  f"({len(result.agent_files)} with agent code)")
            print(f"    Expected:  {sorted(expected_ids) or 'none (clean)'}")
            print(f"    Found:     {sorted(found_ids) or 'none'}")
            print(f"    Chains:    {hit}/{len(expected_chains)} expected "
                  f"cross-file chain(s) detected")
            print(f"    TP={tp} FP={fp} FN={fn}")

            rows.append({
                "project":            project_name,
                "files":              len(result.files),
                "expected":           sorted(expected_ids),
                "found":              sorted(found_ids),
                "cross_file_expected": expected_chains,
                "cross_file_found":   [f.description for f in result.cross_file_findings],
                "tp": tp, "fp": fp, "fn": fn,
            })
        finally:
            if tmp_handle is not None:
                tmp_handle.cleanup()

    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) else 1.0
    recall    = total_tp / (total_tp + total_fn) if (total_tp + total_fn) else 1.0
    f1        = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    print(f"\n{'=' * 66}")
    print(f"  PROJECT BENCHMARK METRICS")
    print(f"{'=' * 66}")
    print(f"    True Positives:  {total_tp}")
    print(f"    False Positives: {total_fp}")
    print(f"    False Negatives: {total_fn}")
    print(f"    Precision: {precision:.3f}  Recall: {recall:.3f}  F1: {f1:.3f}")
    print()
    print(f"    Cross-file chains detected: {chain_hits}/{chain_expected}")
    print(f"    Negative controls clean:    {clean_pass}/{clean_total}")
    print()

    Path(REPORT_DIR).mkdir(exist_ok=True)
    out = Path(REPORT_DIR) / "project_evaluation.json"
    out.write_text(json.dumps({
        "benchmark": "multi-file projects",
        "summary": {
            "true_positives":  total_tp,
            "false_positives": total_fp,
            "false_negatives": total_fn,
            "precision":       round(precision, 3),
            "recall":          round(recall, 3),
            "f1":              round(f1, 3),
            "cross_file_detected": chain_hits,
            "cross_file_expected": chain_expected,
            "negative_controls_clean": f"{clean_pass}/{clean_total}",
        },
        "projects": rows,
    }, indent=2))
    print(f"  Full report: {out}\n")


def cmd_compare(args):
    """Compare AgentGuard against Bandit and Semgrep on the benchmark."""
    from .tool_comparison import run_comparison
    run_comparison(benchmark_dir=args.benchmark_dir)


def cmd_make_ground_truth(args):
    """
    Scan a target and write a ground_truth.json TEMPLATE next to it, pre-filled
    with what AgentGuard found so you only have to correct it by hand.

    This is the answer-key step. full-eval computes precision/recall/F1 by
    comparing findings against this file, so YOU must review it and mark what is
    genuinely present — the tool cannot know ground truth on its own.
    """
    import json as _json
    target = Path(args.target)
    if not target.exists():
        print(f"[ERROR] Target not found: {target}")
        sys.exit(1)

    result, tmp_handle = scan_target(str(target), use_llm=False, verbose=False)
    try:
        gt = {}
        for fr in result.files:
            if not fr.findings:
                continue
            found_ids = sorted({f.vuln_id for f in fr.findings})
            gt[fr.path] = {
                "expected_vulns": found_ids,
                "_note": "REVIEW THIS BY HAND. Remove any vuln_id that is a "
                         "false positive; add any real vuln_id the tool missed. "
                         "This is your ground truth — the accuracy of "
                         "precision/recall depends entirely on getting it right.",
            }
        # include any agent files with no findings, so you can add missed vulns
        for fr in result.files:
            if fr.is_agent_file and fr.path not in gt:
                gt[fr.path] = {
                    "expected_vulns": [],
                    "_note": "No findings here. If you know this file contains a "
                             "vulnerability the tool missed, add its AGT-id.",
                }
    finally:
        if tmp_handle is not None:
            tmp_handle.cleanup()

    out_dir = target if target.is_dir() else target.parent
    out_path = out_dir / "ground_truth.json"
    out_path.write_text(_json.dumps(gt, indent=2))
    print(f"\n  Ground-truth template written: {out_path}")
    print(f"  Files listed: {len(gt)}")
    print(f"\n  NEXT STEPS:")
    print(f"    1. Open {out_path} and correct it by hand:")
    print(f"       - delete any AGT-id that is a false positive")
    print(f"       - add any real AGT-id the tool missed")
    print(f"       - delete the _note lines when done")
    print(f"    2. Then run:")
    print(f"       python3 -m agentguard.main full-eval --target "
          f"{out_dir} --runs 5\n")


def cmd_full_eval(args):
    """Run the complete N-run evaluation covering all dissertation metrics."""
    from .benchmark_runner import run_full_evaluation

    # --target lets you evaluate YOUR OWN code instead of the built-in
    # benchmark. It requires a ground_truth.json inside that folder — generate
    # a starting template with:  make-ground-truth <folder>
    target_dir = getattr(args, "target", None) or args.benchmark_dir
    gt_path = Path(target_dir) / "ground_truth.json"
    if not gt_path.exists():
        print(f"\n[ERROR] No ground_truth.json found in: {target_dir}")
        print(f"\n  full-eval computes precision/recall/F1, which need an answer")
        print(f"  key. Generate a template you can correct by hand:")
        print(f"\n    python3 -m agentguard.main make-ground-truth {target_dir}\n")
        print(f"  Then edit the file and re-run this command with:")
        print(f"    --target {target_dir}\n")
        sys.exit(1)

    run_full_evaluation(
        runs           = args.runs,
        use_llm        = args.with_llm,
        run_validation = not args.no_validation,
        benchmark_dir  = target_dir,
    )


def cmd_evaluate(args):
    """Run scanner + self-validation against benchmark and compute metrics."""
    if getattr(args, "projects", False):
        return cmd_evaluate_projects(args)

    from .validator import validate_findings
    from . import _llm_backend
    import time as _time

    benchmark_dir  = Path("benchmark")
    ground_truth_f = benchmark_dir / "ground_truth.json"

    if not ground_truth_f.exists():
        print(f"[ERROR] Ground truth file not found: {ground_truth_f}")
        sys.exit(1)

    ground_truth: Dict = json.loads(ground_truth_f.read_text())
    all_agt_ids = [v.id for v in AGENT_TOP_10]   # full universe, for FPR/TN

    Path(REPORT_DIR).mkdir(exist_ok=True)
    metrics: Dict[str, dict] = {}
    overall_tp = overall_fp = overall_fn = 0

    # Pre-validation counters (raw scan, before the sandbox stage) — this is
    # the "precision before validation" half of the before/after comparison
    # that tests whether self-validation actually earns its keep.
    pre_tp = pre_fp = pre_fn = 0

    # Per-class confusion matrix across the whole benchmark, for false-positive
    # rate by vulnerability class (FPR = FP / (FP + TN)).
    per_class = {agt: {"tp": 0, "fp": 0, "fn": 0, "tn": 0} for agt in all_agt_ids}

    # Timing — captured per file, reported as both median and mean per the
    # proposal's requirement that a single slow API call shouldn't distort
    # a mean-only report.
    static_times, hybrid_times, validation_times, total_times = [], [], [], []

    with_llm = getattr(args, "with_llm", False)
    if not with_llm:
        from . import analyzer as _a
        _a.ENABLE_LLM_ANALYSIS = False

    _llm_backend.reset_usage()

    print(f"\n{'═'*60}")
    print(f"  AGENTGUARD EVALUATION — Self-Validating Pipeline")
    print(f"{'═'*60}\n")

    for filename, expected in ground_truth.items():
        path = benchmark_dir / filename
        if not path.exists():
            print(f"  [SKIP] {filename} not found")
            continue

        print(f"\n  Scanning + validating: {filename}")
        t_start = _time.perf_counter()

        manifest = parse_agent(str(path))
        t_static_start = _time.perf_counter()
        findings = analyze(manifest)
        t_after_analyze = _time.perf_counter()

        validated = validate_findings(
            findings, manifest,
            use_llm_fallback=with_llm,
            run_benign=False,
            verbose=False,
        )
        t_end = _time.perf_counter()

        # Timing buckets. When the LLM layer is off, "static" and "hybrid" are
        # the same measurement — recorded as such rather than fabricating a
        # separate hybrid number.
        (hybrid_times if with_llm else static_times).append(t_after_analyze - t_static_start)
        validation_times.append(t_end - t_after_analyze)
        total_times.append(t_end - t_start)

        confirmed_vulns = set(v.finding.vuln_id for v in validated
                                if v.bucket == "CONFIRMED")
        raw_vulns = set(f.vuln_id for f in findings)   # pre-validation
        expected_vulns = set(expected.get("expected_vulns", []))

        tp = len(expected_vulns & confirmed_vulns)
        fp = len(confirmed_vulns - expected_vulns)
        fn = len(expected_vulns - confirmed_vulns)

        r_tp = len(expected_vulns & raw_vulns)
        r_fp = len(raw_vulns - expected_vulns)
        r_fn = len(expected_vulns - raw_vulns)
        pre_tp += r_tp; pre_fp += r_fp; pre_fn += r_fn

        # Per-class confusion matrix for this file, across all 10 classes —
        # this is what makes FPR-per-class and TN counts possible.
        for agt in all_agt_ids:
            was_expected = agt in expected_vulns
            was_confirmed = agt in confirmed_vulns
            if was_expected and was_confirmed:
                per_class[agt]["tp"] += 1
            elif was_confirmed and not was_expected:
                per_class[agt]["fp"] += 1
            elif was_expected and not was_confirmed:
                per_class[agt]["fn"] += 1
            else:
                per_class[agt]["tn"] += 1

        precision = tp / (tp + fp) if (tp + fp) > 0 else (1.0 if not expected_vulns else 0.0)
        recall    = tp / (tp + fn) if (tp + fn) > 0 else 1.0
        f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

        metrics[filename] = {
            "expected": sorted(expected_vulns),
            "confirmed": sorted(confirmed_vulns),
            "raw_pre_validation": sorted(raw_vulns),
            "tp": tp, "fp": fp, "fn": fn,
            "precision": round(precision, 3),
            "recall":    round(recall, 3),
            "f1":        round(f1, 3),
            "timing_sec": {
                "static_or_hybrid": round(t_after_analyze - t_static_start, 4),
                "validation":       round(t_end - t_after_analyze, 4),
                "total":            round(t_end - t_start, 4),
            },
        }
        overall_tp += tp; overall_fp += fp; overall_fn += fn

        print(f"    Expected:  {sorted(expected_vulns)}")
        print(f"    Confirmed: {sorted(confirmed_vulns)}")
        print(f"    TP={tp} FP={fp} FN={fn}  P={precision:.2f} R={recall:.2f} F1={f1:.2f}")

    overall_p = overall_tp / (overall_tp + overall_fp) if (overall_tp + overall_fp) > 0 else 0.0
    overall_r = overall_tp / (overall_tp + overall_fn) if (overall_tp + overall_fn) > 0 else 0.0
    overall_f1 = 2 * overall_p * overall_r / (overall_p + overall_r) if (overall_p + overall_r) > 0 else 0.0

    pre_p = pre_tp / (pre_tp + pre_fp) if (pre_tp + pre_fp) > 0 else 0.0
    pre_r = pre_tp / (pre_tp + pre_fn) if (pre_tp + pre_fn) > 0 else 0.0
    pre_f1 = 2 * pre_p * pre_r / (pre_p + pre_r) if (pre_p + pre_r) > 0 else 0.0

    print(f"\n{'═'*60}")
    print(f"  OVERALL METRICS (CONFIRMED-only, i.e. AFTER sandbox validation)")
    print(f"{'═'*60}")
    print(f"    True Positives:  {overall_tp}")
    print(f"    False Positives: {overall_fp}")
    print(f"    False Negatives: {overall_fn}")
    print(f"    Precision: {overall_p:.3f}  Recall: {overall_r:.3f}  F1: {overall_f1:.3f}")

    print(f"\n{'═'*60}")
    print(f"  PRECISION BEFORE vs. AFTER VALIDATION")
    print(f"  (tests whether self-validation reduces false positives)")
    print(f"{'═'*60}")
    print(f"    BEFORE (raw static+LLM findings): "
          f"P={pre_p:.3f} R={pre_r:.3f} F1={pre_f1:.3f}  "
          f"(TP={pre_tp} FP={pre_fp} FN={pre_fn})")
    print(f"    AFTER  (CONFIRMED by sandbox):    "
          f"P={overall_p:.3f} R={overall_r:.3f} F1={overall_f1:.3f}  "
          f"(TP={overall_tp} FP={overall_fp} FN={overall_fn})")
    fp_removed = pre_fp - overall_fp
    print(f"    False positives removed by validation: {fp_removed} "
          f"({fp_removed}/{pre_fp} = "
          f"{(fp_removed/pre_fp*100) if pre_fp else 0:.0f}% of raw FPs)" )

    print(f"\n{'═'*60}")
    print(f"  FALSE-POSITIVE RATE BY VULNERABILITY CLASS")
    print(f"  FPR = FP / (FP + TN)  — computed CONFIRMED-only, per class")
    print(f"{'═'*60}")
    class_fpr = {}
    for agt in all_agt_ids:
        c = per_class[agt]
        fpr = c["fp"] / (c["fp"] + c["tn"]) if (c["fp"] + c["tn"]) > 0 else 0.0
        class_fpr[agt] = round(fpr, 4)
        print(f"    {agt}:  TP={c['tp']} FP={c['fp']} FN={c['fn']} TN={c['tn']}  "
              f"FPR={fpr:.3f}")

    # Negative control — safe_agent.py must produce zero findings.
    safe_findings_count = None
    safe_path = benchmark_dir / "safe_agent.py"
    if safe_path.exists():
        safe_manifest = parse_agent(str(safe_path))
        safe_raw = analyze(safe_manifest)
        safe_validated = validate_findings(
            safe_raw, safe_manifest, use_llm_fallback=with_llm,
            run_benign=False, verbose=False,
        )
        safe_confirmed = [v for v in safe_validated if v.bucket == "CONFIRMED"]
        safe_findings_count = len(safe_confirmed)
        print(f"\n{'═'*60}")
        print(f"  NEGATIVE CONTROL — safe_agent.py")
        print(f"{'═'*60}")
        print(f"    CONFIRMED findings on the safe agent: {safe_findings_count} "
              f"(target: 0)")

    def _median(vals):
        if not vals:
            return None
        s = sorted(vals)
        n = len(s)
        mid = n // 2
        return s[mid] if n % 2 else (s[mid-1] + s[mid]) / 2

    def _mean(vals):
        return sum(vals) / len(vals) if vals else None

    timing_summary = {
        "static_scan_sec":      {"median": _median(static_times),  "mean": _mean(static_times),  "n": len(static_times)},
        "hybrid_scan_sec":      {"median": _median(hybrid_times),  "mean": _mean(hybrid_times),  "n": len(hybrid_times)},
        "sandbox_validation_sec": {"median": _median(validation_times), "mean": _mean(validation_times), "n": len(validation_times)},
        "total_sec":            {"median": _median(total_times),   "mean": _mean(total_times),   "n": len(total_times)},
    }

    print(f"\n{'═'*60}")
    print(f"  SCAN TIME (seconds) — median / mean across {len(total_times)} file(s)")
    print(f"{'═'*60}")
    label = "hybrid (static+LLM)" if with_llm else "static-only"
    active_times = hybrid_times if with_llm else static_times
    print(f"    {label:<24} median={_median(active_times):.4f}  mean={_mean(active_times):.4f}")
    print(f"    sandbox validation      median={_median(validation_times):.4f}  mean={_mean(validation_times):.4f}")
    print(f"    total end-to-end        median={_median(total_times):.4f}  mean={_mean(total_times):.4f}")

    usage = _llm_backend.get_usage()
    print(f"\n{'═'*60}")
    print(f"  ESTIMATED API COST")
    print(f"{'═'*60}")
    print(f"    Provider:           {_llm_backend.LLM_PROVIDER}")
    print(f"    Requests made:      {usage['requests']}")
    print(f"    Input tokens:       {usage['input_tokens']}")
    print(f"    Output tokens:      {usage['output_tokens']}")
    print(f"    Actual cost (free tier): "
          f"${usage['actual_cost_usd']:.4f}" if usage['actual_cost_usd'] is not None
          else "    Actual cost: (paid provider — see your provider's dashboard)")
    print(f"    Reference paid-tier cost estimate: "
          f"${usage['estimated_cost_usd_reference_rate']:.6f} "
          f"(see README, 'Cost accounting', for the rate used)")
    n_files = len(metrics)
    if n_files:
        print(f"    -> per-file average:    "
              f"${usage['estimated_cost_usd_reference_rate']/n_files:.6f}")

    eval_path = Path(REPORT_DIR) / "evaluation.json"
    eval_path.write_text(json.dumps({
        "per_file": metrics,
        "overall_after_validation": {
            "precision": round(overall_p, 3),
            "recall":    round(overall_r, 3),
            "f1":        round(overall_f1, 3),
            "tp": overall_tp, "fp": overall_fp, "fn": overall_fn,
        },
        "overall_before_validation": {
            "precision": round(pre_p, 3),
            "recall":    round(pre_r, 3),
            "f1":        round(pre_f1, 3),
            "tp": pre_tp, "fp": pre_fp, "fn": pre_fn,
        },
        "false_positives_removed_by_validation": fp_removed,
        "per_class_confusion_matrix": per_class,
        "per_class_fpr": class_fpr,
        "negative_control": {
            "file": "safe_agent.py",
            "confirmed_findings": safe_findings_count,
        },
        "timing": timing_summary,
        "api_usage": usage,
    }, indent=2))
    print(f"\n  Full evaluation report: {eval_path}\n")


def cmd_determinism(args):
    """
    Run the single-file benchmark N times (default 5) and check whether
    AgentGuard produces the same outcome every time: same vuln IDs, same file
    locations, same severity levels, same validation classification.

    This directly tests the proposal's determinism target: no more than one
    unique outcome across five consecutive runs.
    """
    from .validator import validate_findings

    n_runs = getattr(args, "runs", 5)
    benchmark_dir  = Path("benchmark")
    ground_truth_f = benchmark_dir / "ground_truth.json"
    if not ground_truth_f.exists():
        print(f"[ERROR] Ground truth file not found: {ground_truth_f}")
        sys.exit(1)
    ground_truth: Dict = json.loads(ground_truth_f.read_text())

    with_llm = getattr(args, "with_llm", False)
    if not with_llm:
        from . import analyzer as _a
        _a.ENABLE_LLM_ANALYSIS = False

    print(f"\n{'═'*60}")
    print(f"  DETERMINISM CHECK — {n_runs} consecutive runs")
    print(f"{'═'*60}")

    # For each run, capture a fingerprint per file: (vuln_id, location,
    # severity, bucket) tuples, sorted. If every run's fingerprint for a file
    # is identical, that file is deterministic.
    run_fingerprints: List[Dict[str, list]] = []

    for run_idx in range(1, n_runs + 1):
        print(f"\n  Run {run_idx}/{n_runs}...")
        fingerprint: Dict[str, list] = {}
        for filename in ground_truth:
            path = benchmark_dir / filename
            if not path.exists():
                continue
            manifest = parse_agent(str(path))
            findings = analyze(manifest)
            validated = validate_findings(
                findings, manifest, use_llm_fallback=with_llm,
                run_benign=False, verbose=False,
            )
            fp = sorted(
                (v.finding.vuln_id, v.finding.location, v.finding.severity, v.bucket)
                for v in validated
            )
            fingerprint[filename] = fp
        run_fingerprints.append(fingerprint)

    # Compare every run's fingerprint against the first run's.
    all_files = sorted(ground_truth.keys())
    mismatches = {}
    for filename in all_files:
        baseline = run_fingerprints[0].get(filename, [])
        for run_idx in range(1, n_runs):
            current = run_fingerprints[run_idx].get(filename, [])
            if current != baseline:
                mismatches.setdefault(filename, []).append({
                    "run": run_idx + 1,
                    "baseline": baseline,
                    "differs_to": current,
                })

    unique_outcomes_per_file = {}
    for filename in all_files:
        seen = []
        for fingerprint in run_fingerprints:
            fp = fingerprint.get(filename, [])
            if fp not in seen:
                seen.append(fp)
        unique_outcomes_per_file[filename] = len(seen)

    total_unique_outcomes = max(unique_outcomes_per_file.values()) if unique_outcomes_per_file else 0

    print(f"\n{'═'*60}")
    print(f"  RESULTS")
    print(f"{'═'*60}")
    for filename in all_files:
        n_unique = unique_outcomes_per_file[filename]
        status = "DETERMINISTIC" if n_unique == 1 else f"NOT DETERMINISTIC ({n_unique} distinct outcomes)"
        print(f"    {filename:<32} {status}")

    print(f"\n  Max distinct outcomes for any single file: {total_unique_outcomes}")
    if total_unique_outcomes <= 1:
        print(f"  PASS — target was 'no more than one unique outcome across "
              f"{n_runs} runs'")
    else:
        print(f"  FAIL — at least one file produced more than one outcome "
              f"across {n_runs} runs")

    Path(REPORT_DIR).mkdir(exist_ok=True)
    out_path = Path(REPORT_DIR) / "determinism_check.json"
    out_path.write_text(json.dumps({
        "n_runs": n_runs,
        "with_llm": with_llm,
        "unique_outcomes_per_file": unique_outcomes_per_file,
        "max_unique_outcomes": total_unique_outcomes,
        "target_met": total_unique_outcomes <= 1,
        "mismatches": mismatches,
        "raw_fingerprints_per_run": run_fingerprints,
    }, indent=2))
    print(f"\n  Full determinism report: {out_path}\n")


def cmd_taxonomy(args):
    """Print the Agent Top 10 taxonomy."""
    print(f"\n{'═'*70}")
    print(f"  THE AGENT TOP 10 — AgentGuard Vulnerability Taxonomy")
    print(f"{'═'*70}\n")
    for v in AGENT_TOP_10:
        print(f"  [{v.id}] {v.name}")
        print(f"     Severity: {v.severity.value}")
        print(f"     {v.description[:100]}...")
        print()


# ─── Argument parser ─────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        prog="agentguard",
        description="AgentGuard — Security scanner for AI agents."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # validate-full command — v0.3 with remediation
    p_vf = sub.add_parser("validate-full",
                            help="v0.3: scan + validate + remediate + verify patches")
    p_vf.add_argument("target", help="Path to agent .py file")
    p_vf.add_argument("--no-llm", action="store_true",
                        help="Skip LLM analysis and adaptive retries")
    p_vf.add_argument("--no-benign", action="store_true",
                        help="Skip differential testing")
    p_vf.add_argument("--no-remediation", action="store_true",
                        help="Skip remediation phase")
    p_vf.set_defaults(func=cmd_validate_full)

    # validate command — full pipeline including sandboxed exploit validation
    p_val = sub.add_parser("validate",
                            help="Scan + validate findings via sandboxed exploits")
    p_val.add_argument("target", help="Path to agent .py file")
    p_val.add_argument("--no-llm", action="store_true",
                        help="Skip LLM analysis and adaptive retries")
    p_val.add_argument("--no-benign", action="store_true",
                        help="Skip differential testing (benign run)")
    p_val.add_argument("--ai-prover-first", action="store_true", dest="ai_prover_first",
                        help="Run the AI-driven prover BEFORE templates, so the AI "
                             "gets first attempt at authoring and executing an exploit "
                             "(demonstrates the AI can independently confirm a vuln)")
    p_val.set_defaults(func=cmd_validate)

    # scan command — accepts a file, a folder, or a zip
    p_scan = sub.add_parser(
        "scan",
        help="Scan an agent file, a project folder, or a .zip archive")
    p_scan.add_argument("target",
                        help="Path to a .py file, a project folder, or a .zip")
    p_scan.add_argument("--no-llm", action="store_true",
                        help="Skip LLM analysis, run static checks only")
    p_scan.add_argument("--verbose", "-v", action="store_true",
                        help="Print per-file progress, capability map, attack paths")
    p_scan.set_defaults(func=cmd_scan)

    # evaluate command
    p_eval = sub.add_parser("evaluate", help="Run benchmark evaluation")
    p_eval.add_argument("--with-llm", action="store_true",
                          help="Enable LLM analysis + adaptive retries")
    p_eval.add_argument("--projects", action="store_true",
                          help="Evaluate the multi-file project benchmark instead")
    p_eval.set_defaults(func=cmd_evaluate)

    # taxonomy command
    p_tax = sub.add_parser("taxonomy", help="Print the Agent Top 10")
    p_tax.set_defaults(func=cmd_taxonomy)

    # providers command
    p_prov = sub.add_parser(
        "providers",
        help="Show the active free LLM backend and test connectivity")
    p_prov.add_argument("--test", action="store_true",
                        help="Send a live test request to the active provider")
    p_prov.set_defaults(func=cmd_providers)

    # full-eval command — the complete dissertation evaluation, N runs
    p_full = sub.add_parser(
        "full-eval",
        help="Run the complete N-run evaluation (all 9 dissertation metrics)")
    p_full.add_argument("--runs", type=int, default=5,
                        help="Number of consecutive runs (default 5)")
    p_full.add_argument("--with-llm", action="store_true",
                        help="Enable the Gemini AI layer (needs an API key)")
    p_full.add_argument("--no-validation", action="store_true",
                        help="Skip the sandbox validation phase")
    p_full.add_argument("--benchmark-dir", default="benchmark",
                        help="Benchmark directory (default: benchmark)")
    p_full.add_argument("--target", default=None,
                        help="Evaluate YOUR folder instead of the built-in "
                             "benchmark (must contain a ground_truth.json — "
                             "generate one with make-ground-truth)")
    p_full.set_defaults(func=cmd_full_eval)

    # make-ground-truth — generate an answer-key template for your own target
    p_gt = sub.add_parser(
        "make-ground-truth",
        help="Scan a target and write a ground_truth.json template to edit by hand")
    p_gt.add_argument("target", help="File, folder, or zip to build an answer key for")
    p_gt.set_defaults(func=cmd_make_ground_truth)

    # compare command — AgentGuard vs Bandit vs Semgrep
    p_cmp = sub.add_parser(
        "compare",
        help="Compare AgentGuard against Bandit and Semgrep (must be installed)")
    p_cmp.add_argument("--benchmark-dir", default="benchmark",
                       help="Benchmark directory (default: benchmark)")
    p_cmp.set_defaults(func=cmd_compare)

    # scan-repeat command — run ANY target N times, check consistency
    p_rep = sub.add_parser(
        "scan-repeat",
        help="Scan any file/folder/zip N times and check the findings are consistent")
    p_rep.add_argument("target",
                       help="Path to a .py file, a project folder, or a .zip")
    p_rep.add_argument("--runs", type=int, default=5,
                       help="Number of consecutive runs (default: 5)")
    p_rep.add_argument("--with-llm", action="store_true",
                       help="Include the AI layer (may make runs non-deterministic)")
    p_rep.set_defaults(func=cmd_scan_repeat)

    # determinism command
    p_det = sub.add_parser(
        "determinism",
        help="Run the benchmark N times and check for identical outcomes")
    p_det.add_argument("--runs", type=int, default=5,
                       help="Number of consecutive runs (default: 5)")
    p_det.add_argument("--with-llm", action="store_true",
                       help="Include the LLM layer (usually run --no-llm-equivalent by default)")
    p_det.set_defaults(func=cmd_determinism)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
