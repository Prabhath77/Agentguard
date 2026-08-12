# Dissertation Evaluation Guide

Every metric your proposal commits to, mapped to one exact command. Run these
in order, on your VM, with a real `GEMINI_API_KEY` exported if you want the
Gemini-inclusive numbers as well as the static-only ones. Every command writes
a JSON file under `reports/` — that JSON is what you transcribe into your
results chapter; don't hand-copy numbers from the console.

Run everything from the repository root (the folder containing `config.py`).

---

## 1–3. Precision, Recall, F1

```bash
python3 -m agentguard.main evaluate
```

Writes `reports/evaluation.json`. Read `overall_after_validation` for the
headline P/R/F1 (this is the number the `F1 ≥ 0.85` target is judged against),
and `per_file` for the per-agent breakdown table.

Run it again with the AI layer included:

```bash
python3 -m agentguard.main evaluate --with-llm
```

Report both. They will likely differ slightly — that difference is itself
worth a sentence in your methodology section (static-only is the
deterministic floor; `--with-llm` shows what the semantic layer adds).

Do the same for the multi-file project benchmark:

```bash
python3 -m agentguard.main evaluate --projects
```

---

## 4. False-positive rate

Same command as above (`evaluate`) already computes everything this section
needs — it's in the same `reports/evaluation.json`:

- **FPR per vulnerability class** — `per_class_fpr` (and the full
  TP/FP/FN/TN breakdown in `per_class_confusion_matrix`)
- **Findings on the safe agent** — `negative_control.confirmed_findings`
  (target: 0)
- **Percentage of safe files incorrectly flagged** — for the single-file
  benchmark there is one negative control (`safe_agent.py`); for the project
  benchmark, `05_research_assistant_safe` is the equivalent — run
  `evaluate --projects` and check its per-project entry
- **Whether sandbox validation removes false positives** — this is answered
  directly by item 8 below; the same JSON has both halves

---

## 5. Determinism across runs

```bash
python3 -m agentguard.main determinism --runs 5
```

Writes `reports/determinism_check.json`. Runs the full benchmark five times
and fingerprints every file's outcome as (vuln ID, location, severity,
validation bucket) tuples — so it checks all four things your proposal asks
for in one pass, not just the vuln IDs. `max_unique_outcomes` is the number to
quote; your target is that it equals 1.

Run it with `--with-llm` too if you want to report on determinism of the AI
layer specifically — note that this is a meaningfully harder bar, since LLM
outputs are not guaranteed deterministic even at temperature 0.

---

## 6. Scan time per agent

Also produced by `evaluate` (step 1–3) — `reports/evaluation.json` →
`timing` block has median and mean for:

- `static_scan_sec` (when run without `--with-llm`)
- `hybrid_scan_sec` (when run with `--with-llm`)
- `sandbox_validation_sec`
- `total_sec`

Both mean and median are recorded specifically because a single slow API call
can distort a mean-only figure — report both in your table.

---

## 7. Estimated cost per scan

Same `evaluate` run, same JSON, `api_usage` block: requests made, input
tokens, output tokens, and a cost estimate.

**Important framing for your write-up:** on the free Gemini/Groq tier, your
*actual* cost is $0 — `api_usage.actual_cost_usd` reports that plainly. The
`estimated_cost_usd_reference_rate` figure is a *hypothetical* — what the same
token volume would cost on a small paid-tier model, using the rate documented
in `_llm_backend.py` (`REFERENCE_RATE_INPUT_PER_1K` /
`REFERENCE_RATE_OUTPUT_PER_1K`). Report both numbers and be explicit about
which is which; presenting the hypothetical as your actual spend would be
misleading.

Per-file and per-project cost: divide the total by the file/project count, or
run `evaluate` and `evaluate --projects` separately and compare their
`api_usage` blocks directly.

---

## 8. Sandboxed validation outcome — before vs. after precision

Also in the same `reports/evaluation.json` from step 1–3:

- `overall_before_validation` — precision/recall/F1 using the *raw* static+AI
  findings, before any exploit is generated or run
- `overall_after_validation` — the same, using only CONFIRMED findings
- `false_positives_removed_by_validation` — the direct count

This is the single most important number for your core contribution: it
answers "does self-validation actually reduce false positives, and by how
much?" with a real measurement rather than an assertion.

---

## 9. Comparison with Bandit, Semgrep, and a manual audit

**Bandit and Semgrep:**

```bash
pip3 install bandit semgrep --break-system-packages
python3 scripts/compare_tools.py                # single-file benchmark
python3 scripts/compare_tools.py --projects      # multi-file benchmark
```

Writes `reports/tool_comparison.json` and `reports/tool_comparison_projects.json`.
Gives you precision/recall/F1/runtime for all three tools side by side, plus
an explicit Agent-Top-10 coverage table (which classes each tool's rule set
can even in principle detect).

Read the header comment in `scripts/compare_tools.py` before you cite these
numbers — it documents exactly how each tool's rule IDs were mapped onto the
Agent Top 10, and states plainly that Bandit and Semgrep have no rule concept
for 7 of the 10 classes. That gap is expected and is the actual finding, not
a configuration artefact — say so in your write-up rather than letting a
reader assume the comparison was rigged in AgentGuard's favour.

The script uses a local, version-pinned Semgrep ruleset
(`scripts/semgrep_rules.yaml`) rather than `--config=auto`, specifically so
the comparison is reproducible — the remote registry config can change
between runs, which would undermine a reproducibility claim.

**Manual audit:**

No script for this one — see `docs/MANUAL_AUDIT_PROTOCOL.md` for the full
procedure. In short: have someone else review the same benchmark files
unaided, time-box it, record what they find, then hand-map their findings to
Agent Top 10 classes yourself and compute the same three numbers.

---

## Bonus — held-out real-world test set

Your proposal also mentions real open-source agents as a held-out set, to
show the benchmark numbers aren't just AgentGuard overfitting to its own test
data. Use the same `scan` command against a real repository:

```bash
git clone https://github.com/huggingface/smolagents.git
python3 -m agentguard.main scan smolagents/src/smolagents --no-llm
python3 -m agentguard.main scan smolagents/src/smolagents
```

There is no ground truth for a held-out set by definition, so you can't
compute P/R/F1 against it — report it qualitatively instead: how many files
scanned without crashing, what it found, and whether the findings look
plausible on manual inspection. This is a robustness claim ("the parser
generalises beyond its own benchmark"), not an accuracy claim, and your
write-up should be explicit about that distinction.

---

## Quick reference — everything in one pass

```bash
# 1-3, 4, 6, 7, 8 — single-file benchmark, static-only
python3 -m agentguard.main evaluate

# same, with the AI layer
python3 -m agentguard.main evaluate --with-llm

# 1-3, 4 for the multi-file benchmark
python3 -m agentguard.main evaluate --projects

# 5 — determinism
python3 -m agentguard.main determinism --runs 5

# 9 — tool comparison
python3 scripts/compare_tools.py
python3 scripts/compare_tools.py --projects

# manual audit — see docs/MANUAL_AUDIT_PROTOCOL.md, done by hand
```

Every one of those writes its own JSON under `reports/` — collect that folder
after the run, it's your appendix.
