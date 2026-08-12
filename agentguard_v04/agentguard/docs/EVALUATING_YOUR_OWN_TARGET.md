# Evaluating Your Own Target (e.g. DVLA) — All 9 Factors

`full-eval` computes precision, recall, and F1. Those three need an **answer
key** — a file stating what vulnerabilities the target genuinely contains. The
tool cannot know that on its own; you establish it by expert review. This is
the standard method for evaluating a scanner on real-world code, and it is
exactly what your dissertation should describe.

Three steps.

## Step 1 — generate the answer-key template

```bash
python3 -m agentguard.main make-ground-truth damn-vulnerable-llm-agent-main/
```

This scans the target and writes `ground_truth.json` inside that folder,
pre-filled with what AgentGuard found, so you are correcting a draft rather than
writing from scratch.

## Step 2 — correct it by hand (this is the important part)

Open the `ground_truth.json` it created. For each file:

- **Delete** any `AGT-id` that is a false positive (the tool flagged it, but it
  is not really a vulnerability).
- **Add** any `AGT-id` that is a real vulnerability the tool missed.
- Delete the `_note` lines when you are done.

This manual judgement is your ground truth. Getting it right is your
responsibility as the researcher — the honesty of every precision/recall number
depends on it. Do not just accept the tool's own output as truth, or precision
is guaranteed to be 1.0 and means nothing.

For DVLA specifically, its documented purpose is prompt-injection via
Thought/Action/Observation, and manual review also shows SQL injection in the
data layer and an unsafe tool chain. Mark what you can actually justify.

## Step 3 — run the full evaluation, N times

```bash
python3 -m agentguard.main full-eval --target damn-vulnerable-llm-agent-main/ --runs 5
```

This runs 5 times and produces all 9 factors against your answer key:

1. Precision  2. Recall  3. F1  4. False-positive rate  5. Determinism across
the 5 runs  6. Scan time  7. API cost  8. Validation buckets + precision before
vs after validation.

(Factor 9, comparison with Bandit/Semgrep, is the separate `compare` command.)

Add `--with-llm` to include the AI layer and get real token/cost numbers.

Results are written to `reports/full_evaluation_5runs_<timestamp>.{json,md}`.

## Why precision won't (and shouldn't) be 1.0 when you do it properly

If you run `full-eval` immediately on the auto-generated template without
editing it, precision will be 1.0 — because the answer key was copied from the
findings, so everything "matches." That number is meaningless. The real result
comes after Step 2, when you have marked the tool's actual mistakes. A precision
below 1.0 is not a failure; it is a credible, defensible measurement.
