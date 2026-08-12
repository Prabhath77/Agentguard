# AgentGuard Evaluation Results

Runs: **5** · LLM: **off** · Validation: **on** · Generated: 2026-08-12T01:36:35.362723+00:00

## Headline metrics (mean across runs)

| Metric | Mean | Median | Min | Max | Std dev | Target | Pass |
|--------|------|--------|-----|-----|---------|--------|------|
| Precision | 0.773 | 0.773 | 0.773 | 0.773 | 0.000 | ≥ 0.85 | no |
| Recall | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | ≥ 0.85 | yes |
| F1 | 0.872 | 0.872 | 0.872 | 0.872 | 0.000 | ≥ 0.85 | yes |

## Determinism

- Runs: 5
- Unique outcomes: **1**
- Target: no more than one unique outcome across five runs
- Result: **PASS**

## False-positive rate

- Findings on safe agents: **0**
- Safe files flagged: **0 / 1**
- Percentage of safe files flagged: **0.0%**

## Scan time per agent (seconds)

| Phase | Mean | Median | Min | Max |
|-------|------|--------|-----|-----|
| Static only | 0.010 | 0.010 | 0.005 | 0.012 |
| Hybrid (+LLM) | 0.010 | 0.010 | 0.005 | 0.012 |
| Validation | 2.432 | 2.300 | 2.208 | 2.988 |
| Total | 2.438 | 2.305 | 2.211 | 2.999 |

## Estimated API cost

| Item | Mean | Median |
|------|------|--------|
| Cost (USD, whole run) | 0.000000 | 0.000000 |
| API requests | 0 | 0 |
| Input tokens | 0 | 0 |
| Output tokens | 0 | 0 |

## Sandboxed validation — the core contribution

Buckets (run 1): {'CONFIRMED': 31, 'SUSPECTED': 8, 'DISMISSED': 6}

| | Precision |
|--|-----------|
| Before validation | 0.773 |
| After validation | 0.812 |
| Change | +0.040 |

This comparison directly tests the central claim: whether self-validation reduces false positives.
