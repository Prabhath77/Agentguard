# =============================================================================
# repeat_runner.py — Repeat a scan N times on ANY target
# =============================================================================
# full-eval (benchmark_runner.py) answers "how good is AgentGuard on the
# labeled benchmark" — it needs ground truth to compute precision/recall.
#
# This module answers a different, equally real question: "if I scan THIS
# file/folder/zip N times, do I get the same answer every time, how long does
# it take, and what does it cost?" There is no ground truth for an arbitrary
# real-world target, so precision/recall/F1 are not computed here — only what
# can honestly be measured without knowing the correct answer in advance:
#
#   - determinism (identical findings across all N runs?)
#   - finding counts, by severity and by vuln class
#   - timing (mean, median, min, max)
#   - cost (tokens, requests, USD) if the LLM layer ran
#   - validation buckets (CONFIRMED/SUSPECTED/DISMISSED) if validation ran
# =============================================================================

import json
import time
import datetime
import statistics
from pathlib import Path
from typing import Dict, List
from collections import defaultdict

from .benchmark_runner import _agg   # reuse the mean/median/min/max/stdev helper


def _run_once(target: str, use_llm: bool, run_validation: bool) -> Dict:
    """One scan of the given target. Returns everything this run produced."""
    from .project_scanner import scan_target
    from .cost_monitor import reset_cost_tracker, get_cost_report

    reset_cost_tracker()

    t0 = time.perf_counter()
    result, tmp_handle = scan_target(target, use_llm=use_llm, verbose=False)
    try:
        scan_time = time.perf_counter() - t0

        buckets = {"CONFIRMED": 0, "SUSPECTED": 0, "DISMISSED": 0}
        validation_time = 0.0

        if run_validation:
            from .validator import validate_findings
            t1 = time.perf_counter()
            for file_result in result.agent_files:
                if not file_result.findings:
                    continue
                validated = validate_findings(
                    file_result.findings, file_result.manifest,
                    use_llm_fallback=use_llm, run_benign=True,
                )
                for v in validated:
                    if v.bucket in buckets:
                        buckets[v.bucket] += 1
            validation_time = time.perf_counter() - t1

        findings = result.all_findings
        by_severity = defaultdict(int)
        by_class = defaultdict(int)
        for f in findings:
            by_severity[f.severity] += 1
            by_class[f.vuln_id] += 1

        # Determinism signature: every (location, vuln_id, severity), sorted.
        signature = sorted(
            f"{f.location}:{f.vuln_id}:{f.severity}" for f in findings
        )

        cost = get_cost_report()

        return {
            "total_findings": len(findings),
            "by_severity":     dict(by_severity),
            "by_class":        dict(by_class),
            "cross_file_chains": len(result.cross_file_findings),
            "files_scanned":   len(result.files),
            "timing": {
                "scan_s":       round(scan_time, 4),
                "validation_s": round(validation_time, 4),
                "total_s":      round(scan_time + validation_time, 4),
            },
            "cost": {
                "input_tokens":  cost.total_input_tokens,
                "output_tokens": cost.total_output_tokens,
                "api_requests":  cost.total_calls,
                "cost_usd":      round(cost.total_cost_usd, 6),
            },
            "validation_buckets": buckets,
            "signature": signature,
        }
    finally:
        if tmp_handle is not None:
            tmp_handle.cleanup()


def run_repeated_scan(target: str,
                      runs: int = 5,
                      use_llm: bool = False,
                      run_validation: bool = False,
                      output_dir: str = "reports") -> Dict:
    """Scan `target` `runs` times and report determinism, timing, and cost."""
    print(f"\n{'=' * 70}")
    print(f"  AGENTGUARD REPEAT SCAN — {runs} run(s)")
    print(f"  Target: {target}")
    print(f"  LLM: {'ON' if use_llm else 'OFF (static only)'}  |  "
          f"Validation: {'ON' if run_validation else 'OFF'}")
    print(f"{'=' * 70}")

    per_run: List[Dict] = []
    for i in range(1, runs + 1):
        print(f"\n  ── Run {i}/{runs} ──")
        t0 = time.perf_counter()
        result = _run_once(target, use_llm, run_validation)
        wall = time.perf_counter() - t0
        result["wall_clock_s"] = round(wall, 2)
        per_run.append(result)

        print(f"     findings: {result['total_findings']}  "
              f"(by severity: {result['by_severity']})")
        if run_validation:
            print(f"     validation buckets: {result['validation_buckets']}")
        print(f"     time: {wall:.2f}s")

    # ── Determinism ─────────────────────────────────────────────────────────
    signatures = ["|".join(r["signature"]) for r in per_run]
    unique_outcomes = len(set(signatures))

    # ── Aggregate ────────────────────────────────────────────────────────────
    def collect(fn):
        return [fn(r) for r in per_run]

    aggregate = {
        "total_findings":   _agg(collect(lambda r: float(r["total_findings"]))),
        "scan_time_s":      _agg(collect(lambda r: r["timing"]["scan_s"])),
        "validation_time_s": _agg(collect(lambda r: r["timing"]["validation_s"])),
        "total_time_s":     _agg(collect(lambda r: r["timing"]["total_s"])),
        "cost_usd":         _agg(collect(lambda r: r["cost"]["cost_usd"])),
        "api_requests":     _agg(collect(lambda r: float(r["cost"]["api_requests"]))),
        "input_tokens":     _agg(collect(lambda r: float(r["cost"]["input_tokens"]))),
        "output_tokens":    _agg(collect(lambda r: float(r["cost"]["output_tokens"]))),
    }

    report = {
        "meta": {
            "tool":        "AgentGuard v0.4",
            "timestamp":   datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "target":      str(target),
            "runs":        runs,
            "llm_enabled": use_llm,
            "validation":  run_validation,
        },
        "determinism": {
            "runs":            runs,
            "unique_outcomes": unique_outcomes,
            "deterministic":   unique_outcomes == 1,
        },
        "aggregate": aggregate,
        "per_run": per_run,
    }

    print(f"\n{'=' * 70}")
    print(f"  AGGREGATE RESULTS  ({runs} runs)")
    print(f"{'=' * 70}")
    print(f"\n  Determinism: {unique_outcomes} unique outcome(s) across {runs} runs "
          f"({'DETERMINISTIC' if unique_outcomes == 1 else 'NON-DETERMINISTIC'})")
    print(f"\n  Findings per run: mean={aggregate['total_findings']['mean']:.1f} "
          f"median={aggregate['total_findings']['median']:.1f} "
          f"min={aggregate['total_findings']['min']:.0f} "
          f"max={aggregate['total_findings']['max']:.0f}")
    print(f"\n  Timing (seconds):")
    for label, key in [("Scan", "scan_time_s"), ("Validation", "validation_time_s"),
                       ("Total", "total_time_s")]:
        a = aggregate[key]
        print(f"    {label:<12} mean={a['mean']:.3f}  median={a['median']:.3f}  "
              f"min={a['min']:.3f}  max={a['max']:.3f}  stdev={a['stdev']}")
    if use_llm:
        print(f"\n  Cost (across all {runs} runs):")
        print(f"    Total cost:    ${sum(r['cost']['cost_usd'] for r in per_run):.6f}")
        print(f"    Mean per run:  ${aggregate['cost_usd']['mean']:.6f}")
        print(f"    API requests:  mean={aggregate['api_requests']['mean']:.1f}")

    out_dir = Path(output_dir)
    out_dir.mkdir(exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_name = Path(str(target)).stem or "target"
    json_path = out_dir / f"repeat_scan_{safe_name}_{runs}runs_{stamp}.json"
    md_path   = out_dir / f"repeat_scan_{safe_name}_{runs}runs_{stamp}.md"
    json_path.write_text(json.dumps(report, indent=2))
    _write_markdown(report, md_path)

    print(f"\n  JSON:     {json_path}")
    print(f"  Markdown: {md_path}\n")
    return report


def _write_markdown(report: Dict, path: Path) -> None:
    m = report["meta"]
    det = report["determinism"]
    agg = report["aggregate"]

    md = [
        f"# Repeat Scan — {m['target']}",
        "",
        f"Runs: **{m['runs']}** · LLM: **{'on' if m['llm_enabled'] else 'off'}** · "
        f"Validation: **{'on' if m['validation'] else 'off'}** · "
        f"Generated: {m['timestamp']}",
        "",
        "## Determinism",
        "",
        f"- Unique outcomes across {det['runs']} runs: **{det['unique_outcomes']}**",
        f"- Result: **{'DETERMINISTIC' if det['deterministic'] else 'NON-DETERMINISTIC'}**",
        "",
        "## Findings per run",
        "",
        f"Mean **{agg['total_findings']['mean']:.1f}**, "
        f"median **{agg['total_findings']['median']:.1f}**, "
        f"range [{agg['total_findings']['min']:.0f}, {agg['total_findings']['max']:.0f}]",
        "",
        "## Timing (seconds)",
        "",
        "| Phase | Mean | Median | Min | Max | Std dev |",
        "|-------|------|--------|-----|-----|---------|",
    ]
    for label, key in [("Scan", "scan_time_s"), ("Validation", "validation_time_s"),
                       ("Total", "total_time_s")]:
        a = agg[key]
        md.append(f"| {label} | {a['mean']:.3f} | {a['median']:.3f} "
                  f"| {a['min']:.3f} | {a['max']:.3f} | {a['stdev']} |")
    md.append("")

    if m["llm_enabled"]:
        md.append("## Cost")
        md.append("")
        md.append(f"- Mean cost per run: ${agg['cost_usd']['mean']:.6f}")
        md.append(f"- Mean API requests per run: {agg['api_requests']['mean']:.1f}")
        md.append(f"- Mean input tokens per run: {agg['input_tokens']['mean']:.0f}")
        md.append(f"- Mean output tokens per run: {agg['output_tokens']['mean']:.0f}")
        md.append("")

    md.append("## Per-run detail")
    md.append("")
    md.append("| Run | Findings | Scan (s) | Validation (s) | Buckets |")
    md.append("|-----|----------|----------|-----------------|---------|")
    for i, r in enumerate(report["per_run"], 1):
        md.append(f"| {i} | {r['total_findings']} | {r['timing']['scan_s']:.3f} "
                  f"| {r['timing']['validation_s']:.3f} | {r['validation_buckets']} |")
    md.append("")

    path.write_text("\n".join(md))
