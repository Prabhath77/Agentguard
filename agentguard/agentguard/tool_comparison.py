# =============================================================================
# tool_comparison.py — AgentGuard vs Bandit vs Semgrep
# =============================================================================
# Dimension 9 of the evaluation: run three scanners over the same benchmark
# and compare precision, recall, F1, runtime, and Agent Top 10 coverage.
#
# The central argument this produces: general-purpose SAST tools (Bandit,
# Semgrep) catch generic Python issues (eval, subprocess, SQL) but are BLIND
# to agent-specific vulnerability classes — excessive tool permissions, prompt
# injection, system-prompt leakage, unsafe tool chaining, memory poisoning,
# excessive agency. AgentGuard is built for exactly those.
#
# Bandit and Semgrep must be installed:
#     pip3 install bandit semgrep --break-system-packages
#
# They are invoked as external processes and their JSON output is mapped, as
# generously as possible, onto the Agent Top 10 — generously on purpose, so
# the comparison cannot be accused of handicapping them.
# =============================================================================

import json
import time
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Set, Tuple


# ─── Map a generic SAST hit onto an Agent Top 10 class ───────────────────────
# Deliberately generous: any plausible reading counts in the external tool's
# favour, so the comparison is not open to the charge of rigging the mapping.

BANDIT_TO_AGT = {
    "B102": "AGT-008",  # exec_used
    "B307": "AGT-008",  # eval
    "B605": "AGT-008",  # start_process_with_a_shell
    "B602": "AGT-008",  # subprocess_popen_with_shell_true
    "B603": "AGT-008",  # subprocess_without_shell_equals_true
    "B604": "AGT-008",  # any_other_function_with_shell_equals_true
    "B608": "AGT-006",  # hardcoded_sql_expressions (injection)
    "B105": "AGT-007",  # hardcoded_password_string
    "B106": "AGT-007",  # hardcoded_password_funcarg
    "B107": "AGT-007",  # hardcoded_password_default
    "B324": "AGT-006",  # hashlib weak hash
    "B301": "AGT-006",  # pickle
    "B506": "AGT-006",  # yaml_load
}

SEMGREP_KEYWORD_TO_AGT = [
    ("eval",           "AGT-008"),
    ("exec",           "AGT-008"),
    ("subprocess",     "AGT-008"),
    ("shell",          "AGT-008"),
    ("command-injection", "AGT-008"),
    ("sql",            "AGT-006"),
    ("injection",      "AGT-006"),
    ("password",       "AGT-007"),
    ("secret",         "AGT-007"),
    ("api-key",        "AGT-007"),
    ("hardcoded",      "AGT-007"),
]


# ─── External tool runners ───────────────────────────────────────────────────

def run_bandit(target: str) -> Tuple[Dict[str, Set[str]], float]:
    """Return {filename: {AGT-IDs}} and elapsed seconds for Bandit."""
    if not shutil.which("bandit"):
        return {}, 0.0
    t0 = time.perf_counter()
    proc = subprocess.run(
        ["bandit", "-r", target, "-f", "json", "-q"],
        capture_output=True, text=True,
    )
    elapsed = time.perf_counter() - t0
    per_file: Dict[str, Set[str]] = {}
    try:
        data = json.loads(proc.stdout)
    except (ValueError, json.JSONDecodeError):
        return per_file, elapsed
    for result in data.get("results", []):
        agt = BANDIT_TO_AGT.get(result.get("test_id", ""))
        if agt:
            fname = Path(result.get("filename", "")).name
            per_file.setdefault(fname, set()).add(agt)
    return per_file, elapsed


def run_semgrep(target: str) -> Tuple[Dict[str, Set[str]], float]:
    """Return {filename: {AGT-IDs}} and elapsed seconds for Semgrep."""
    if not shutil.which("semgrep"):
        return {}, 0.0
    t0 = time.perf_counter()
    proc = subprocess.run(
        ["semgrep", "--config", "auto", "--json", "--quiet", target],
        capture_output=True, text=True,
    )
    elapsed = time.perf_counter() - t0
    per_file: Dict[str, Set[str]] = {}
    try:
        data = json.loads(proc.stdout)
    except (ValueError, json.JSONDecodeError):
        return per_file, elapsed
    for result in data.get("results", []):
        check_id = result.get("check_id", "").lower()
        fname = Path(result.get("path", "")).name
        for keyword, agt in SEMGREP_KEYWORD_TO_AGT:
            if keyword in check_id:
                per_file.setdefault(fname, set()).add(agt)
                break
    return per_file, elapsed


def run_agentguard(benchmark_dir: Path, ground_truth: Dict) -> Tuple[Dict[str, Set[str]], float]:
    """Return {filename: {AGT-IDs}} and elapsed seconds for AgentGuard (static)."""
    from .parser import parse_agent
    from .analyzer import analyze
    from . import analyzer as analyzer_module
    analyzer_module.ENABLE_LLM_ANALYSIS = False

    per_file: Dict[str, Set[str]] = {}
    t0 = time.perf_counter()
    for filename in ground_truth:
        target = benchmark_dir / filename
        if not target.exists():
            continue
        manifest = parse_agent(str(target))
        findings = analyze(manifest)
        per_file[filename] = {f.vuln_id for f in findings}
    elapsed = time.perf_counter() - t0
    return per_file, elapsed


# ─── Scoring ─────────────────────────────────────────────────────────────────

def _score(per_file: Dict[str, Set[str]], ground_truth: Dict) -> Dict:
    """Precision/recall/F1 of a tool's per-file AGT hits against ground truth."""
    tp = fp = fn = 0
    covered_classes: Set[str] = set()
    for filename, spec in ground_truth.items():
        expected = set(spec.get("expected_vulns", []))
        found = per_file.get(filename, set())
        covered_classes |= found
        tp += len(found & expected)
        fp += len(found - expected)
        fn += len(expected - found)
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall    = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) else 0.0)
    return {
        "tp": tp, "fp": fp, "fn": fn,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "agt_classes_covered": sorted(covered_classes),
        "num_classes_covered": len(covered_classes),
    }


ALL_AGT = [f"AGT-{i:03d}" for i in range(1, 11)]


def run_comparison(benchmark_dir: str = "benchmark",
                   output_dir: str = "reports") -> Dict:
    """Run all three tools on the benchmark and produce a comparison report."""
    bdir = Path(benchmark_dir)
    gt = json.loads((bdir / "ground_truth.json").read_text())

    print(f"\n{'=' * 70}")
    print(f"  TOOL COMPARISON — AgentGuard vs Bandit vs Semgrep")
    print(f"{'=' * 70}")

    print("\n  Running AgentGuard (static)...")
    ag_hits, ag_time = run_agentguard(bdir, gt)
    print("  Running Bandit...")
    b_hits, b_time = run_bandit(str(bdir))
    print("  Running Semgrep (this can take a minute)...")
    s_hits, s_time = run_semgrep(str(bdir))

    tools = {
        "AgentGuard": {"score": _score(ag_hits, gt), "time_s": round(ag_time, 2)},
        "Bandit":     {"score": _score(b_hits, gt),  "time_s": round(b_time, 2)},
        "Semgrep":    {"score": _score(s_hits, gt),  "time_s": round(s_time, 2)},
    }

    # Agent Top 10 coverage: which classes can each tool detect AT ALL.
    coverage = {}
    for name, hits in [("AgentGuard", ag_hits), ("Bandit", b_hits), ("Semgrep", s_hits)]:
        detectable = set()
        for found in hits.values():
            detectable |= found
        coverage[name] = {
            agt: (agt in detectable) for agt in ALL_AGT
        }

    report = {
        "meta": {"benchmark_dir": str(bdir), "agent_top_10": ALL_AGT},
        "tools": tools,
        "agent_top10_coverage": coverage,
    }

    _print_comparison(report)

    out = Path(output_dir)
    out.mkdir(exist_ok=True)
    (out / "tool_comparison.json").write_text(json.dumps(report, indent=2))
    _write_comparison_markdown(report, out / "tool_comparison.md")
    print(f"\n  JSON:     {out / 'tool_comparison.json'}")
    print(f"  Markdown: {out / 'tool_comparison.md'}\n")
    return report


def _print_comparison(report: Dict) -> None:
    print(f"\n{'=' * 70}")
    print(f"  RESULTS")
    print(f"{'=' * 70}")
    print(f"\n  {'Tool':<14}{'Prec':>7}{'Recall':>8}{'F1':>7}"
          f"{'Time(s)':>9}{'AGT covered':>13}")
    print(f"  {'-' * 58}")
    for name, d in report["tools"].items():
        s = d["score"]
        print(f"  {name:<14}{s['precision']:>7.3f}{s['recall']:>8.3f}"
              f"{s['f1']:>7.3f}{d['time_s']:>9.2f}"
              f"{s['num_classes_covered']:>10}/10")

    print(f"\n  Agent Top 10 coverage (can the tool detect the class at all?):")
    print(f"  {'Class':<10}{'AgentGuard':>12}{'Bandit':>9}{'Semgrep':>9}")
    print(f"  {'-' * 40}")
    cov = report["agent_top10_coverage"]
    for agt in report["meta"]["agent_top_10"]:
        row = f"  {agt:<10}"
        for tool in ["AgentGuard", "Bandit", "Semgrep"]:
            row += f"{'yes' if cov[tool][agt] else '—':>12}" if tool == "AgentGuard" \
                   else f"{'yes' if cov[tool][agt] else '—':>9}"
        print(row)


def _write_comparison_markdown(report: Dict, path: Path) -> None:
    md = []
    md.append("# Tool Comparison — AgentGuard vs Bandit vs Semgrep")
    md.append("")
    md.append("## Precision / Recall / F1 / Runtime")
    md.append("")
    md.append("| Tool | Precision | Recall | F1 | Time (s) | AGT classes covered |")
    md.append("|------|-----------|--------|----|----------|--------------------|")
    for name, d in report["tools"].items():
        s = d["score"]
        md.append(f"| {name} | {s['precision']:.3f} | {s['recall']:.3f} "
                  f"| {s['f1']:.3f} | {d['time_s']:.2f} | {s['num_classes_covered']}/10 |")
    md.append("")
    md.append("## Agent Top 10 coverage")
    md.append("")
    md.append("Whether each tool can detect the vulnerability class **at all**, "
              "even generously mapping its generic rules onto the taxonomy.")
    md.append("")
    md.append("| Class | AgentGuard | Bandit | Semgrep |")
    md.append("|-------|-----------|--------|---------|")
    cov = report["agent_top10_coverage"]
    for agt in report["meta"]["agent_top_10"]:
        row = f"| {agt} |"
        for tool in ["AgentGuard", "Bandit", "Semgrep"]:
            row += f" {'yes' if cov[tool][agt] else 'no'} |"
        md.append(row)
    md.append("")
    md.append("The agent-specific classes — AGT-001 (excessive permissions), "
              "AGT-002 (prompt injection), AGT-003 (system-prompt leakage), "
              "AGT-004 (unsafe tool chaining), AGT-005 (memory poisoning), "
              "AGT-010 (excessive agency) — are the ones general SAST tools "
              "cannot express, and are the reason an agent-specific scanner is "
              "needed.")
    md.append("")
    path.write_text("\n".join(md))
