# AgentGuard — Evaluation Testing Procedure

This is the exact, ordered procedure to produce every result your dissertation
proposal commits to. Run it top to bottom. Every command writes timestamped
files to `reports/` — those files are your evidence; keep them.

Nothing here is destructive, and everything except the AI and comparison steps
runs offline with no API key.

---

## Before you start

```bash
cd ~/Downloads/agentguard          # wherever you unzipped it
pip3 install -r requirements.txt --break-system-packages
```

For the two optional steps you also need:

```bash
# For the AI-layer runs (Section 2 findings, cost/token numbers):
export GEMINI_API_KEY="AQ...your-key"
export GEMINI_MODEL="gemini-flash-latest"

# For the tool comparison (installed by the requirements file above):
bandit --version && semgrep --version
```

---

## The one command that produces most of it

The `full-eval` command runs the benchmark N times and computes dimensions
1–8 in a single pass. `--runs` is the number you asked for — say 5 and it runs
five times, say 3 and it runs three, and it aggregates across all of them.

```bash
python3 -m agentguard.main full-eval --runs 5
```

This one run gives you, aggregated across all 5 runs with mean / median / min /
max / standard deviation:

| Proposal dimension | Where it appears in the output |
|--------------------|--------------------------------|
| 1. Precision | "Precision / Recall / F1" block |
| 2. Recall | same block |
| 3. F1 | same block |
| 4. False-positive rate | "False-positive rate" block (findings on safe agents, % safe files flagged) |
| 5. Determinism across runs | "Determinism" block (unique outcomes across the runs) |
| 6. Scan time per agent | "Scan time" block (static / hybrid / validation / total, mean AND median) |
| 7. Estimated API cost | "Estimated API cost" block (tokens, requests, cost) |
| 8. Sandboxed validation outcome | "Validation buckets" + "Precision before vs after validation" |

It writes two files:

- `reports/full_evaluation_5runs_<timestamp>.json` — every raw number, per run
- `reports/full_evaluation_5runs_<timestamp>.md` — clean tables to paste into the dissertation

### Run it three ways

To fill in every cell of the proposal, run `full-eval` in three configurations
and keep all three output files:

```bash
# (a) Static + validation, no AI — the deterministic headline numbers.
#     This is what your F1 = 0.889 claim rests on. Fully reproducible.
python3 -m agentguard.main full-eval --runs 5

# (b) Static only, no validation — isolates raw static-analysis timing/precision.
python3 -m agentguard.main full-eval --runs 5 --no-validation

# (c) Hybrid: static + AI + validation — the full pipeline, and the ONLY
#     configuration that produces real token/cost numbers (dimension 7).
#     Requires GEMINI_API_KEY. Costs a few tenths of a cent total.
python3 -m agentguard.main full-eval --runs 5 --with-llm
```

Note on determinism: configurations (a) and (b) are deterministic and should
report **1 unique outcome** across 5 runs. Configuration (c) uses the LLM, which
is *not* guaranteed deterministic even at temperature 0 — if (c) shows more than
one unique outcome, that is a real and reportable finding, not a bug. Report
determinism from (a), and report (c)'s variability honestly alongside it.

---

## Dimension 9 — comparison with existing tools

Separate command, because Bandit and Semgrep run as external programs:

```bash
python3 -m agentguard.main compare
```

Produces precision, recall, F1, runtime, and Agent Top 10 coverage for
AgentGuard vs Bandit vs Semgrep on the same benchmark, written to
`reports/tool_comparison.{json,md}`.

The expected shape of this result — and the argument it supports — is that the
general-purpose tools catch generic Python issues (eval, subprocess, hardcoded
secrets) but cannot express the agent-specific classes (AGT-001, 002, 003, 004,
005, 010). Report their recall honestly: it is low here precisely because those
classes are outside their design, which is the point.

For the **manual security audit** third of dimension 9, that part is by
definition manual: you (or a peer) review each benchmark agent by hand, record
which vulnerabilities you find and how long it took, and tabulate that against
AgentGuard. There is no command for it — it is human baseline data you collect
once.

---

## The held-out real-world test

Your proposal commits to testing on real open-source agents to reduce benchmark
bias. Scan a real project and keep the report:

```bash
# Example — clone a real agent repo first, then:
python3 -m agentguard.main scan /path/to/real_agent_project --no-llm
python3 -m agentguard.main scan /path/to/real_agent_project      # with AI, if key set
```

For the real-world set you will not have ground truth, so you cannot compute
precision/recall automatically. Instead report: how many findings, of what
classes, how many you manually judged true vs false on inspection, and whether
the tool ran to completion without crashing on code neither you nor the tool's
author wrote. Parser robustness on unseen real code is itself a result worth
stating.

---

## What to save for the write-up

After the runs above, `reports/` contains everything. For the dissertation you
want to keep, per configuration:

1. The `.md` table files from each `full-eval` run (a, b, c).
2. `tool_comparison.md`.
3. At least one full per-project report (`*_project_report.md`) as an appendix
   example of the tool's output.
4. Your manual-audit table (collected by hand).
5. Your real-world scan reports.

Back up the whole `reports/` folder somewhere before you re-run anything, since
new runs add new timestamped files but you do not want to lose the set you
analysed.

---

## Quick reference — every evaluation command

```bash
# All of dimensions 1-8, N runs, aggregated:
python3 -m agentguard.main full-eval --runs 5                 # static + validation
python3 -m agentguard.main full-eval --runs 5 --no-validation # static only
python3 -m agentguard.main full-eval --runs 5 --with-llm      # full pipeline + cost

# Dimension 9:
python3 -m agentguard.main compare                            # vs Bandit + Semgrep

# The original single-run benchmarks (still available):
python3 -m agentguard.main evaluate                           # single-file, 1 run
python3 -m agentguard.main evaluate --projects                # multi-file projects
```
