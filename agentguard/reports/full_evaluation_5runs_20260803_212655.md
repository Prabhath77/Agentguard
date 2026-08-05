# AgentGuard Evaluation Results

Runs: **5** · LLM: **off** · Validation: **on** · Generated: 2026-08-03T20:26:55.091944+00:00

## Headline metrics (mean across runs)

| Metric | Mean | Median | Min | Max | Std dev | Target | Pass |
|--------|------|--------|-----|-----|---------|--------|------|
| Precision | 0.500 | 0.500 | 0.500 | 0.500 | 0.000 | ≥ 0.85 | no |
| Recall | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | ≥ 0.85 | yes |
| F1 | 0.667 | 0.667 | 0.667 | 0.667 | 0.000 | ≥ 0.85 | no |

## Determinism

- Runs: 5
- Unique outcomes: **1**
- Target: no more than one unique outcome across five runs
- Result: **PASS**

## False-positive rate

- Findings on safe agents: **0**
- Safe files flagged: **0 / 0**
- Percentage of safe files flagged: **0.0%**

## Scan time per agent (seconds)

| Phase | Mean | Median | Min | Max |
|-------|------|--------|-----|-----|
| Static only | 0.014 | 0.016 | 0.008 | 0.019 |
| Hybrid (+LLM) | 0.014 | 0.016 | 0.008 | 0.019 |
| Validation | 2.852 | 2.791 | 2.693 | 3.157 |
| Total | 2.866 | 2.807 | 2.703 | 3.173 |

## Estimated API cost

| Item | Mean | Median |
|------|------|--------|
| Cost (USD, whole run) | 0.000000 | 0.000000 |
| API requests | 0 | 0 |
| Input tokens | 0 | 0 |
| Output tokens | 0 | 0 |

## Sandboxed validation — the core contribution

Buckets (run 1): {'CONFIRMED': 2, 'SUSPECTED': 3, 'DISMISSED': 0}

| | Precision |
|--|-----------|
| Before validation | 0.500 |
| After validation | 1.000 |
| Change | +0.500 |

This comparison directly tests the central claim: whether self-validation reduces false positives.
