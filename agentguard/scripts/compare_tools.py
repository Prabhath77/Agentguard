#!/usr/bin/env python3
# =============================================================================
# scripts/compare_tools.py — AgentGuard vs Bandit vs Semgrep
# =============================================================================
# Runs all three tools against the same benchmark files and the same ground
# truth, and reports precision/recall/F1/runtime/coverage side by side.
#
# THE MAPPING PROBLEM, STATED HONESTLY:
# Bandit and Semgrep have no concept of the Agent Top 10 — they check for
# generic Python security issues (eval/exec, shell=True, weak hashes, ...).
# To compare them on equal footing, each tool's rule ID is mapped to the
# closest matching AGT class via BANDIT_TO_AGT / SEMGREP_TO_AGT below. This
# mapping is a judgment call, documented here rather than hidden, and it is
# necessarily approximate — for example Bandit's B102 (exec_used) maps to
# AGT-008 (Unsafe Code Execution), which is a reasonable match, but Bandit has
# no rule that corresponds to AGT-001 (Excessive Tool Permissions), AGT-002
# (Prompt Injection in Tool Description), AGT-003 (System Prompt Leakage),
# AGT-004 (Unsafe Tool Chaining), AGT-005 (Memory Poisoning), AGT-009 (Missing
# Output Filtering), or AGT-010 (Excessive Agency) at all — those classes are
# agent-specific concepts that a generic Python security scanner has no rule
# category for. That gap is the entire point of running this comparison: it
# is expected to show up as recall the generic tools cannot achieve by
# construction, not as a flaw in how they were configured here.
#
# Usage:
#   python3 scripts/compare_tools.py
#   python3 scripts/compare_tools.py --projects   # multi-file benchmark instead
# =============================================================================

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SEMGREP_RULES = REPO_ROOT / "scripts" / "semgrep_rules.yaml"

# ─── Rule-ID → Agent Top 10 mapping (documented, approximate) ────────────────

BANDIT_TO_AGT = {
    "B102": "AGT-008",  # exec_used
    "B307": "AGT-008",  # eval
    "B602": "AGT-008",  # subprocess shell=True
    "B603": "AGT-008",  # subprocess without shell but still exec-adjacent
    "B605": "AGT-008",  # os.system / start process with shell
    "B604": "AGT-008",  # any function with shell equals true
    "B301": "AGT-006",  # pickle load — unsafe deserialization / input handling
    "B506": "AGT-006",  # yaml load
    "B105": "AGT-007",  # hardcoded password string
    "B106": "AGT-007",  # hardcoded password func arg
    "B107": "AGT-007",  # hardcoded password default
    "B108": "AGT-007",  # hardcoded tmp path (loosely — config/secrets hygiene)
    "B324": "AGT-007",  # weak hash used in a security context (loosely, hygiene)
    "B608": "AGT-006",  # hardcoded SQL expressions — closest match is input validation
}

SEMGREP_TO_AGT = {
    "python-eval-exec-use":              "AGT-008",
    "python-subprocess-shell-true":      "AGT-008",
    "python-os-system":                  "AGT-008",
    "python-hardcoded-secret-assignment": "AGT-007",
    "python-sql-string-formatting":       "AGT-006",
    "python-pickle-load":                 "AGT-006",
    "python-yaml-unsafe-load":            "AGT-006",
    "python-requests-tls-verify-false":   "AGT-007",
    "python-weak-hash":                   "AGT-007",
    "python-jwt-no-verify":               "AGT-007",
}

ALL_AGT_IDS = [f"AGT-{i:03d}" for i in range(1, 11)]


def run_bandit(py_file: Path) -> set:
    """Return the set of AGT IDs Bandit's findings map to for one file."""
    try:
        proc = subprocess.run(
            ["bandit", "-f", "json", str(py_file)],
            capture_output=True, text=True, timeout=30,
        )
        data = json.loads(proc.stdout) if proc.stdout else {"results": []}
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as e:
        print(f"    [bandit error on {py_file.name}: {e}]")
        return set()

    agt_ids = set()
    for result in data.get("results", []):
        test_id = result.get("test_id", "")
        if test_id in BANDIT_TO_AGT:
            agt_ids.add(BANDIT_TO_AGT[test_id])
    return agt_ids


def run_semgrep(py_file: Path) -> set:
    """Return the set of AGT IDs Semgrep's findings map to for one file."""
    try:
        proc = subprocess.run(
            ["semgrep", "--config", str(SEMGREP_RULES),
             str(py_file), "--json", "--quiet"],
            capture_output=True, text=True, timeout=60,
        )
        data = json.loads(proc.stdout) if proc.stdout else {"results": []}
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as e:
        print(f"    [semgrep error on {py_file.name}: {e}]")
        return set()

    agt_ids = set()
    for result in data.get("results", []):
        check_id = result.get("check_id", "").rsplit(".", 1)[-1]
        if check_id in SEMGREP_TO_AGT:
            agt_ids.add(SEMGREP_TO_AGT[check_id])
    return agt_ids


def run_agentguard(py_file: Path) -> set:
    """Return the set of AGT IDs AgentGuard's static analyzer finds (--no-llm equivalent)."""
    sys.path.insert(0, str(REPO_ROOT))
    from agentguard import analyzer as A
    A.ENABLE_LLM_ANALYSIS = False
    from agentguard.parser import parse_agent
    from agentguard.analyzer import analyze

    manifest = parse_agent(str(py_file))
    findings = analyze(manifest)
    return set(f.vuln_id for f in findings)


def precision_recall_f1(found: set, expected: set) -> tuple:
    tp = len(found & expected)
    fp = len(found - expected)
    fn = len(expected - found)
    p = tp / (tp + fp) if (tp + fp) else (1.0 if not expected else 0.0)
    r = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * p * r / (p + r) if (p + r) else 0.0
    return p, r, f1, tp, fp, fn


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--projects", action="store_true",
                        help="Use the multi-file project benchmark instead")
    args = parser.parse_args()

    if args.projects:
        bench_dir = REPO_ROOT / "benchmark_projects"
        gt_file = bench_dir / "project_ground_truth.json"
    else:
        bench_dir = REPO_ROOT / "benchmark"
        gt_file = bench_dir / "ground_truth.json"

    ground_truth = json.loads(gt_file.read_text())

    tools_totals = {
        "agentguard": {"tp": 0, "fp": 0, "fn": 0, "time": 0.0},
        "bandit":     {"tp": 0, "fp": 0, "fn": 0, "time": 0.0},
        "semgrep":    {"tp": 0, "fp": 0, "fn": 0, "time": 0.0},
    }
    per_file_results = {}

    for name, spec in ground_truth.items():
        if args.projects:
            target = bench_dir / name
            py_files = list(target.rglob("*.py")) if target.is_dir() else []
            expected = set(spec.get("expected_findings", []))
        else:
            target = bench_dir / name
            py_files = [target] if target.exists() else []
            expected = set(spec.get("expected_vulns", []))

        if not py_files:
            continue

        print(f"\n  {name}")
        file_result = {"expected": sorted(expected)}

        for tool_name, run_fn in [("agentguard", run_agentguard),
                                   ("bandit", run_bandit),
                                   ("semgrep", run_semgrep)]:
            t0 = time.perf_counter()
            found = set()
            for f in py_files:
                found |= run_fn(f)
            elapsed = time.perf_counter() - t0

            p, r, f1, tp, fp, fn = precision_recall_f1(found, expected)
            tools_totals[tool_name]["tp"] += tp
            tools_totals[tool_name]["fp"] += fp
            tools_totals[tool_name]["fn"] += fn
            tools_totals[tool_name]["time"] += elapsed

            file_result[tool_name] = {
                "found": sorted(found), "tp": tp, "fp": fp, "fn": fn,
                "precision": round(p, 3), "recall": round(r, 3), "f1": round(f1, 3),
                "time_sec": round(elapsed, 4),
            }
            print(f"    {tool_name:<12} found={sorted(found)!s:<40} "
                  f"P={p:.2f} R={r:.2f} F1={f1:.2f} ({elapsed:.3f}s)")

        per_file_results[name] = file_result

    print(f"\n{'='*70}")
    print(f"  OVERALL COMPARISON")
    print(f"{'='*70}")
    print(f"  {'Tool':<12} {'Precision':>10} {'Recall':>10} {'F1':>8} {'Total time':>12}")
    overall = {}
    for tool_name, totals in tools_totals.items():
        tp, fp, fn = totals["tp"], totals["fp"], totals["fn"]
        p = tp / (tp + fp) if (tp + fp) else 0.0
        r = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * p * r / (p + r) if (p + r) else 0.0
        overall[tool_name] = {
            "precision": round(p, 3), "recall": round(r, 3), "f1": round(f1, 3),
            "total_time_sec": round(totals["time"], 3),
            "tp": tp, "fp": fp, "fn": fn,
        }
        print(f"  {tool_name:<12} {p:>10.3f} {r:>10.3f} {f1:>8.3f} {totals['time']:>10.3f}s")

    print(f"\n  NOTE: Bandit and Semgrep have no rule concept for AGT-001, 002, 003,")
    print(f"  004, 005, 009, or 010 — those are agent-specific classes with no")
    print(f"  generic-Python equivalent. Their recall gap on those classes reflects")
    print(f"  a scope limitation of generic tools, not a configuration choice made")
    print(f"  here. See scripts/compare_tools.py header for the full rule mapping.")

    coverage = {
        "agentguard": ALL_AGT_IDS,
        "bandit": sorted(set(BANDIT_TO_AGT.values())),
        "semgrep": sorted(set(SEMGREP_TO_AGT.values())),
    }
    print(f"\n  AGT CLASS COVERAGE (by rule mapping, not by result on this benchmark):")
    for tool_name, classes in coverage.items():
        missing = sorted(set(ALL_AGT_IDS) - set(classes))
        print(f"    {tool_name:<12} covers {len(classes)}/10: {classes}")
        if missing:
            print(f"    {'':<12} no rule for: {missing}")

    report_dir = REPO_ROOT / "reports"
    report_dir.mkdir(exist_ok=True)
    suffix = "_projects" if args.projects else ""
    out_path = report_dir / f"tool_comparison{suffix}.json"
    out_path.write_text(json.dumps({
        "per_file": per_file_results,
        "overall": overall,
        "agt_class_coverage_by_rule_mapping": coverage,
        "mapping_bandit": BANDIT_TO_AGT,
        "mapping_semgrep": SEMGREP_TO_AGT,
    }, indent=2))
    print(f"\n  Full comparison report: {out_path}\n")


if __name__ == "__main__":
    main()
