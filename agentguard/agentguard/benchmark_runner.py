# =============================================================================
# benchmark_runner.py — Comprehensive Evaluation Harness
# =============================================================================
# Runs the AgentGuard benchmark N times and computes every metric the
# dissertation proposal commits to, in one pass:
#
#   1. Precision, Recall, F1 (per class and overall)
#   2. False-positive rate (per class, on safe agents, % files flagged)
#   3. Determinism across the N runs (unique outcomes)
#   4. Scan time (static-only, hybrid, validation, end-to-end; mean AND median)
#   5. Estimated API cost (tokens, requests, per-file, per-project)
#   6. Sandboxed validation outcome (CONFIRMED/SUSPECTED/DISMISSED)
#   7. Precision before vs after validation — the core-contribution test
#   8. All of the above aggregated with mean/median/stdev across runs
#
# (Comparison against Bandit/Semgrep/manual audit — dimension 9 — is handled
# separately by tool_comparison.py, since those tools must be installed and
# invoked as external processes.)
#
# Output: a timestamped JSON with every per-run and aggregate number, plus a
# readable console summary and a Markdown table block ready to paste into the
# dissertation.
# =============================================================================

import json
import time
import statistics
import datetime
from pathlib import Path
from typing import Dict, List, Tuple
from collections import defaultdict


# ─── Metric helpers ──────────────────────────────────────────────────────────

def _prf(tp: int, fp: int, fn: int) -> Tuple[float, float, float]:
    """Precision, recall, F1 from raw counts."""
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall    = tp / (tp + fn) if (tp + fn) else 1.0
    f1        = (2 * precision * recall / (precision + recall)
                 if (precision + recall) else 0.0)
    return precision, recall, f1


def _agg(values: List[float]) -> Dict[str, float]:
    """Mean / median / min / max / stdev for a list of numbers."""
    if not values:
        return {"mean": 0.0, "median": 0.0, "min": 0.0, "max": 0.0, "stdev": 0.0}
    return {
        "mean":   round(statistics.mean(values), 4),
        "median": round(statistics.median(values), 4),
        "min":    round(min(values), 4),
        "max":    round(max(values), 4),
        "stdev":  round(statistics.pstdev(values), 4) if len(values) > 1 else 0.0,
    }


# ─── A single benchmark run ──────────────────────────────────────────────────

def _run_once(benchmark_dir: Path, ground_truth: Dict,
              use_llm: bool, run_validation: bool) -> Dict:
    """
    One full pass over the benchmark. Returns every raw number this run
    produced, so the aggregator can compute cross-run statistics later.
    """
    from .parser import parse_agent
    from .analyzer import analyze, Finding
    from . import analyzer as analyzer_module
    from .cost_monitor import reset_cost_tracker, get_cost_report

    reset_cost_tracker()

    # Per-class tallies, both before and after validation.
    class_tp_pre  = defaultdict(int)
    class_fp_pre  = defaultdict(int)
    class_fn_pre  = defaultdict(int)
    class_tp_post = defaultdict(int)
    class_fp_post = defaultdict(int)
    class_fn_post = defaultdict(int)

    buckets = {"CONFIRMED": 0, "SUSPECTED": 0, "DISMISSED": 0}
    safe_agent_findings = 0
    safe_files_flagged  = 0
    safe_files_total    = 0

    per_file_time_static = []
    per_file_time_hybrid = []
    per_file_time_valid  = []
    per_file_time_total  = []

    # A stable, comparable signature of this run's output, for determinism.
    outcome_signature = []

    for filename in sorted(ground_truth.keys()):
        target = benchmark_dir / filename
        if not target.exists():
            continue

        spec = ground_truth[filename]
        expected = set(spec.get("expected_vulns", []))
        is_safe  = (len(expected) == 0) or ("safe" in filename.lower())
        if is_safe:
            safe_files_total += 1

        # ── Static-only timing ────────────────────────────────────────────
        analyzer_module.ENABLE_LLM_ANALYSIS = False
        t0 = time.perf_counter()
        manifest = parse_agent(str(target))
        static_findings = analyze(manifest)
        t_static = time.perf_counter() - t0
        per_file_time_static.append(t_static)

        # ── Hybrid (static + LLM) timing ──────────────────────────────────
        if use_llm:
            analyzer_module.ENABLE_LLM_ANALYSIS = True
            t0 = time.perf_counter()
            manifest = parse_agent(str(target))
            hybrid_findings = analyze(manifest)
            t_hybrid = time.perf_counter() - t0
            findings_for_eval = hybrid_findings
        else:
            t_hybrid = t_static
            findings_for_eval = static_findings
        per_file_time_hybrid.append(t_hybrid)

        # ── Pre-validation scoring (what the scanner reports before sandbox) ─
        found_ids = {f.vuln_id for f in findings_for_eval}
        for vid in found_ids:
            if vid in expected:
                class_tp_pre[vid] += 1
            else:
                class_fp_pre[vid] += 1
        for vid in expected - found_ids:
            class_fn_pre[vid] += 1

        if is_safe:
            safe_agent_findings += len(findings_for_eval)
            if findings_for_eval:
                safe_files_flagged += 1

        # ── Validation (sandbox) timing + post-validation scoring ─────────
        confirmed_ids = found_ids   # default if validation disabled
        t_valid = 0.0
        if run_validation:
            from .validator import validate_findings
            t0 = time.perf_counter()
            validated = validate_findings(
                findings_for_eval, manifest,
                use_llm_fallback=use_llm, run_benign=True,
            )
            t_valid = time.perf_counter() - t0

            confirmed_ids = set()
            for v in validated:
                buckets[v.bucket] = buckets.get(v.bucket, 0) + 1
                if v.bucket == "CONFIRMED":
                    confirmed_ids.add(v.finding.vuln_id)

            for vid in confirmed_ids:
                if vid in expected:
                    class_tp_post[vid] += 1
                else:
                    class_fp_post[vid] += 1
            for vid in expected - confirmed_ids:
                class_fn_post[vid] += 1
        per_file_time_valid.append(t_valid)

        per_file_time_total.append(t_static + (t_hybrid - t_static) + t_valid)

        # Determinism signature: sorted (file, vuln_id, severity) tuples.
        for f in sorted(findings_for_eval, key=lambda x: (x.vuln_id, x.severity)):
            outcome_signature.append(f"{filename}:{f.vuln_id}:{f.severity}")

    # ── Roll per-class into overall ───────────────────────────────────────
    tp_pre  = sum(class_tp_pre.values())
    fp_pre  = sum(class_fp_pre.values())
    fn_pre  = sum(class_fn_pre.values())
    p_pre, r_pre, f1_pre = _prf(tp_pre, fp_pre, fn_pre)

    if run_validation:
        tp_post = sum(class_tp_post.values())
        fp_post = sum(class_fp_post.values())
        fn_post = sum(class_fn_post.values())
        p_post, r_post, f1_post = _prf(tp_post, fp_post, fn_post)
    else:
        tp_post, fp_post, fn_post = tp_pre, fp_pre, fn_pre
        p_post, r_post, f1_post = p_pre, r_pre, f1_pre

    cost = get_cost_report()

    return {
        "pre_validation":  {"tp": tp_pre, "fp": fp_pre, "fn": fn_pre,
                             "precision": round(p_pre, 4), "recall": round(r_pre, 4),
                             "f1": round(f1_pre, 4)},
        "post_validation": {"tp": tp_post, "fp": fp_post, "fn": fn_post,
                             "precision": round(p_post, 4), "recall": round(r_post, 4),
                             "f1": round(f1_post, 4)},
        "per_class_pre": {
            vid: dict(zip(("precision", "recall", "f1"),
                          [round(x, 4) for x in _prf(class_tp_pre[vid],
                                                     class_fp_pre[vid],
                                                     class_fn_pre[vid])]))
            for vid in set(class_tp_pre) | set(class_fp_pre) | set(class_fn_pre)
        },
        "false_positives": {
            "safe_agent_findings":     safe_agent_findings,
            "safe_files_flagged":      safe_files_flagged,
            "safe_files_total":        safe_files_total,
            "pct_safe_files_flagged":  round(
                100 * safe_files_flagged / safe_files_total, 1
            ) if safe_files_total else 0.0,
            "fp_by_class_pre":  dict(class_fp_pre),
            "fp_by_class_post": dict(class_fp_post),
        },
        "validation_buckets": buckets,
        "timing": {
            "static_s":     _agg(per_file_time_static),
            "hybrid_s":     _agg(per_file_time_hybrid),
            "validation_s": _agg(per_file_time_valid),
            "total_s":      _agg(per_file_time_total),
        },
        "cost": {
            "input_tokens":  cost.total_input_tokens,
            "output_tokens": cost.total_output_tokens,
            "api_requests":  cost.total_calls,
            "cost_usd":      round(cost.total_cost_usd, 6),
            "files_scanned": len(per_file_time_total),
            "cost_per_file": round(
                cost.total_cost_usd / len(per_file_time_total), 6
            ) if per_file_time_total else 0.0,
        },
        "outcome_signature": outcome_signature,
    }


# ─── The N-run driver ────────────────────────────────────────────────────────

def run_full_evaluation(runs: int = 5,
                        use_llm: bool = False,
                        run_validation: bool = True,
                        benchmark_dir: str = "benchmark",
                        output_dir: str = "reports") -> Dict:
    """
    Run the benchmark `runs` times and compute all dissertation metrics with
    per-run detail and cross-run aggregate statistics.
    """
    bdir = Path(benchmark_dir)
    gt_file = bdir / "ground_truth.json"
    if not gt_file.exists():
        raise FileNotFoundError(f"Ground truth not found: {gt_file}")
    ground_truth = json.loads(gt_file.read_text())

    print(f"\n{'=' * 70}")
    print(f"  AGENTGUARD FULL EVALUATION — {runs} run(s)")
    print(f"  LLM: {'ON' if use_llm else 'OFF (static only)'}  |  "
          f"Validation: {'ON' if run_validation else 'OFF'}")
    print(f"{'=' * 70}")

    per_run: List[Dict] = []
    for i in range(1, runs + 1):
        print(f"\n  ── Run {i}/{runs} ──")
        t0 = time.perf_counter()
        result = _run_once(bdir, ground_truth, use_llm, run_validation)
        elapsed = time.perf_counter() - t0
        result["wall_clock_s"] = round(elapsed, 2)
        per_run.append(result)

        pre  = result["pre_validation"]
        post = result["post_validation"]
        print(f"     pre-validation:  P={pre['precision']:.3f} "
              f"R={pre['recall']:.3f} F1={pre['f1']:.3f}")
        print(f"     post-validation: P={post['precision']:.3f} "
              f"R={post['recall']:.3f} F1={post['f1']:.3f}")
        print(f"     buckets: {result['validation_buckets']}")
        print(f"     wall clock: {elapsed:.1f}s")

    # ── Determinism: how many unique output signatures across runs ─────────
    signatures = ["|".join(r["outcome_signature"]) for r in per_run]
    unique_outcomes = len(set(signatures))

    # ── Aggregate the headline numbers across runs ─────────────────────────
    def collect(path_fn):
        return [path_fn(r) for r in per_run]

    aggregate = {
        "precision_pre":  _agg(collect(lambda r: r["pre_validation"]["precision"])),
        "recall_pre":     _agg(collect(lambda r: r["pre_validation"]["recall"])),
        "f1_pre":         _agg(collect(lambda r: r["pre_validation"]["f1"])),
        "precision_post": _agg(collect(lambda r: r["post_validation"]["precision"])),
        "recall_post":    _agg(collect(lambda r: r["post_validation"]["recall"])),
        "f1_post":        _agg(collect(lambda r: r["post_validation"]["f1"])),
        "static_time_s":  _agg(collect(lambda r: r["timing"]["static_s"]["median"])),
        "hybrid_time_s":  _agg(collect(lambda r: r["timing"]["hybrid_s"]["median"])),
        "validation_time_s": _agg(collect(lambda r: r["timing"]["validation_s"]["median"])),
        "total_time_s":   _agg(collect(lambda r: r["timing"]["total_s"]["median"])),
        "cost_usd":       _agg(collect(lambda r: r["cost"]["cost_usd"])),
        "api_requests":   _agg(collect(lambda r: float(r["cost"]["api_requests"]))),
        "input_tokens":   _agg(collect(lambda r: float(r["cost"]["input_tokens"]))),
        "output_tokens":  _agg(collect(lambda r: float(r["cost"]["output_tokens"]))),
        "pct_safe_files_flagged": _agg(
            collect(lambda r: r["false_positives"]["pct_safe_files_flagged"])),
    }

    report = {
        "meta": {
            "tool":           "AgentGuard v0.4",
            "timestamp":      datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "runs":           runs,
            "llm_enabled":    use_llm,
            "validation":     run_validation,
            "benchmark_dir":  str(bdir),
        },
        "determinism": {
            "runs":                 runs,
            "unique_outcomes":      unique_outcomes,
            "deterministic":        unique_outcomes == 1,
            "target":               "<= 1 unique outcome across 5 runs",
            "meets_target":         unique_outcomes <= 1,
        },
        "aggregate": aggregate,
        "targets": {
            "precision >= 0.85": aggregate["precision_pre"]["mean"] >= 0.85,
            "recall >= 0.85":    aggregate["recall_pre"]["mean"] >= 0.85,
            "f1 >= 0.85":        aggregate["f1_pre"]["mean"] >= 0.85,
        },
        "validation_effect": {
            "precision_before": aggregate["precision_pre"]["mean"],
            "precision_after":  aggregate["precision_post"]["mean"],
            "improvement":      round(
                aggregate["precision_post"]["mean"]
                - aggregate["precision_pre"]["mean"], 4),
        },
        "per_run": per_run,
    }

    out_dir = Path(output_dir)
    out_dir.mkdir(exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = out_dir / f"full_evaluation_{runs}runs_{stamp}.json"
    out_path.write_text(json.dumps(report, indent=2))

    _print_summary(report)
    _write_markdown_tables(report, out_dir / f"full_evaluation_{runs}runs_{stamp}.md")
    print(f"\n  Full JSON:     {out_path}")
    print(f"  Markdown tables: {out_dir / f'full_evaluation_{runs}runs_{stamp}.md'}\n")
    return report


# ─── Console summary ─────────────────────────────────────────────────────────

def _print_summary(report: Dict) -> None:
    agg = report["aggregate"]
    det = report["determinism"]
    ve  = report["validation_effect"]

    def line(label, m, pct=False):
        f = (lambda x: f"{x*100:.1f}%") if pct else (lambda x: f"{x:.4f}")
        print(f"    {label:<26} mean={f(m['mean'])}  median={f(m['median'])}  "
              f"min={f(m['min'])}  max={f(m['max'])}  stdev={m['stdev']}")

    print(f"\n{'=' * 70}")
    print(f"  AGGREGATE RESULTS  ({report['meta']['runs']} runs)")
    print(f"{'=' * 70}")

    print(f"\n  [1-3] Precision / Recall / F1 (pre-validation)")
    line("Precision", agg["precision_pre"])
    line("Recall",    agg["recall_pre"])
    line("F1",        agg["f1_pre"])

    print(f"\n  Targets (>= 0.85):")
    for k, v in report["targets"].items():
        print(f"    {'PASS' if v else 'FAIL'}  {k}")

    print(f"\n  [4] False-positive rate")
    line("% safe files flagged", agg["pct_safe_files_flagged"])

    print(f"\n  [5] Determinism across {det['runs']} runs")
    print(f"    unique outcomes: {det['unique_outcomes']}  "
          f"({'DETERMINISTIC' if det['deterministic'] else 'NON-DETERMINISTIC'})")
    print(f"    meets target (<=1): {'PASS' if det['meets_target'] else 'FAIL'}")

    print(f"\n  [6] Scan time per agent (seconds, median-of-medians)")
    line("Static only",    agg["static_time_s"])
    line("Hybrid (+LLM)",  agg["hybrid_time_s"])
    line("Validation",     agg["validation_time_s"])
    line("Total",          agg["total_time_s"])

    print(f"\n  [7] Estimated API cost")
    line("Cost USD (whole run)", agg["cost_usd"])
    line("API requests",         agg["api_requests"])
    line("Input tokens",         agg["input_tokens"])
    line("Output tokens",        agg["output_tokens"])

    print(f"\n  [8] Validation buckets (run 1)")
    print(f"    {report['per_run'][0]['validation_buckets']}")

    print(f"\n  [8b] Precision before vs after validation — THE KEY TEST")
    print(f"    before: {ve['precision_before']:.4f}")
    print(f"    after:  {ve['precision_after']:.4f}")
    print(f"    change: {ve['improvement']:+.4f}")
    print()


# ─── Markdown tables for the dissertation ────────────────────────────────────

def _write_markdown_tables(report: Dict, path: Path) -> None:
    agg = report["aggregate"]
    det = report["determinism"]
    ve  = report["validation_effect"]
    m = report["meta"]

    md = []
    md.append(f"# AgentGuard Evaluation Results")
    md.append("")
    md.append(f"Runs: **{m['runs']}** · LLM: **{'on' if m['llm_enabled'] else 'off'}** · "
              f"Validation: **{'on' if m['validation'] else 'off'}** · "
              f"Generated: {m['timestamp']}")
    md.append("")
    md.append("## Headline metrics (mean across runs)")
    md.append("")
    md.append("| Metric | Mean | Median | Min | Max | Std dev | Target | Pass |")
    md.append("|--------|------|--------|-----|-----|---------|--------|------|")
    rows = [
        ("Precision", agg["precision_pre"], "≥ 0.85"),
        ("Recall",    agg["recall_pre"],    "≥ 0.85"),
        ("F1",        agg["f1_pre"],        "≥ 0.85"),
    ]
    for name, a, tgt in rows:
        passed = "yes" if a["mean"] >= 0.85 else "no"
        md.append(f"| {name} | {a['mean']:.3f} | {a['median']:.3f} | {a['min']:.3f} "
                  f"| {a['max']:.3f} | {a['stdev']:.3f} | {tgt} | {passed} |")
    md.append("")

    md.append("## Determinism")
    md.append("")
    md.append(f"- Runs: {det['runs']}")
    md.append(f"- Unique outcomes: **{det['unique_outcomes']}**")
    md.append(f"- Target: no more than one unique outcome across five runs")
    md.append(f"- Result: **{'PASS' if det['meets_target'] else 'FAIL'}**")
    md.append("")

    md.append("## False-positive rate")
    md.append("")
    fp = report["per_run"][0]["false_positives"]
    md.append(f"- Findings on safe agents: **{fp['safe_agent_findings']}**")
    md.append(f"- Safe files flagged: **{fp['safe_files_flagged']} / {fp['safe_files_total']}**")
    md.append(f"- Percentage of safe files flagged: "
              f"**{agg['pct_safe_files_flagged']['mean']:.1f}%**")
    md.append("")

    md.append("## Scan time per agent (seconds)")
    md.append("")
    md.append("| Phase | Mean | Median | Min | Max |")
    md.append("|-------|------|--------|-----|-----|")
    for name, key in [("Static only", "static_time_s"), ("Hybrid (+LLM)", "hybrid_time_s"),
                      ("Validation", "validation_time_s"), ("Total", "total_time_s")]:
        a = agg[key]
        md.append(f"| {name} | {a['mean']:.3f} | {a['median']:.3f} "
                  f"| {a['min']:.3f} | {a['max']:.3f} |")
    md.append("")

    md.append("## Estimated API cost")
    md.append("")
    md.append("| Item | Mean | Median |")
    md.append("|------|------|--------|")
    md.append(f"| Cost (USD, whole run) | {agg['cost_usd']['mean']:.6f} "
              f"| {agg['cost_usd']['median']:.6f} |")
    md.append(f"| API requests | {agg['api_requests']['mean']:.0f} "
              f"| {agg['api_requests']['median']:.0f} |")
    md.append(f"| Input tokens | {agg['input_tokens']['mean']:.0f} "
              f"| {agg['input_tokens']['median']:.0f} |")
    md.append(f"| Output tokens | {agg['output_tokens']['mean']:.0f} "
              f"| {agg['output_tokens']['median']:.0f} |")
    md.append("")

    md.append("## Sandboxed validation — the core contribution")
    md.append("")
    md.append(f"Buckets (run 1): {report['per_run'][0]['validation_buckets']}")
    md.append("")
    md.append("| | Precision |")
    md.append("|--|-----------|")
    md.append(f"| Before validation | {ve['precision_before']:.3f} |")
    md.append(f"| After validation | {ve['precision_after']:.3f} |")
    md.append(f"| Change | {ve['improvement']:+.3f} |")
    md.append("")
    md.append("This comparison directly tests the central claim: whether "
              "self-validation reduces false positives.")
    md.append("")

    path.write_text("\n".join(md))
