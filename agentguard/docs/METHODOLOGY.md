# Research Methodology — AgentGuard

This document describes the experimental methodology used to evaluate AgentGuard. It is intended as a reference for the dissertation's Methodology and Evaluation chapters.

---

## Research Paradigm

This project follows a **design science research** paradigm — building an artefact (the scanner) and evaluating it against measurable success criteria. This is distinct from:
- *Empirical* studies (observing existing systems)
- *Theoretical* studies (proving properties mathematically)

Design science is appropriate because no existing tool addresses this problem; the artefact itself is the contribution.

---

## Threat Model

We assume:
- The agent codebase is honest (developer is not malicious)
- The LLM provider is honest
- The attacker can submit arbitrary inputs to the deployed agent (prompt injection, malicious content in fetched URLs, poisoned data)
- The attacker may also influence external data sources the agent reads from (RAG corpora, web pages, third-party APIs)

We do NOT defend against:
- Malicious LLM model providers (out of scope)
- Compromise of the host operating system
- Side-channel attacks on the LLM itself

---

## Building The Benchmark

The benchmark consists of agents annotated with ground truth labels for the vulnerabilities they contain.

### Construction methodology

Each vulnerable benchmark agent was constructed by:

1. Selecting a vulnerability class from the Agent Top 10
2. Designing a **realistic** agent function that a developer might plausibly build (customer service, math tutor, research assistant — not synthetic toy code)
3. Introducing the vulnerability *as it would manifest in practice*, not as a contrived snippet
4. Annotating with a comment describing the vulnerability for reproducibility
5. Adding the expected vulnerability IDs to `ground_truth.json`

### Negative control

`safe_agent.py` follows good security practice on every dimension. The scanner should produce **zero findings**. If it produces findings, those are by definition false positives.

### Why this benchmark methodology is defensible

- **Reproducible** — anyone can scan the same agents
- **Extensible** — new vulnerability examples can be added incrementally
- **Realistic** — based on real agent patterns, not toy examples
- **Open** — published with the tool

---

## Evaluation Metrics

### Per-finding metrics

For each scan, we compute:

- **True Positive (TP)** — scanner found a vulnerability that exists in ground truth
- **False Positive (FP)** — scanner found a vulnerability that is NOT in ground truth
- **False Negative (FN)** — scanner missed a vulnerability that IS in ground truth

From these:

$$
\text{Precision} = \frac{TP}{TP + FP}
$$

$$
\text{Recall} = \frac{TP}{TP + FN}
$$

$$
F_1 = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}
$$

Precision tells us: *of the things we flagged, how many were real?*  
Recall tells us: *of the real vulnerabilities, how many did we catch?*  
F1 is the harmonic mean — balances both.

### Granularity decisions

We evaluate at the **vulnerability class level per file**, not per individual finding. This means if the scanner finds 3 instances of AGT-007 in one file and the ground truth lists AGT-007 once, that counts as 1 TP. We do not double-count.

This decision is justified because vulnerability *classes* are what consumers of the report act on; multiple instances of the same class represent the same underlying flaw.

### Aggregation

We report:
- Per-file metrics (visible in evaluation output)
- Overall (micro-averaged) precision, recall, F1 across all files

---

## Experimental Configurations

We evaluate three configurations:

| Configuration | Description |
|---------------|-------------|
| **Static-only** | Pattern matching, AST analysis, capability graph only — no LLM |
| **LLM-only** | Disable static detectors; use only LLM reasoning |
| **Hybrid** | Both — static for deterministic, LLM for semantic |

This decomposition lets us measure the *value added* by the LLM layer.

---

## Real-World Evaluation

After benchmark evaluation, we run the scanner against real OSS agents:

1. Clone target repositories
2. Run AgentGuard on relevant agent files
3. Manually verify each finding
4. Categorise as: True / False / Arguable
5. For confirmed vulnerabilities in OSS projects, follow responsible disclosure

This produces a second precision number — *real-world precision* — which is more meaningful than benchmark precision because real code has noise our benchmark does not.

---

## Threats To Validity

### Internal validity

- **Ground truth bias** — the benchmark is constructed by the researcher; the same person might construct the scanner to find what they planted. **Mitigation:** include real OSS agents in evaluation as Tier 2.
- **Detector tuning to benchmark** — risk of overfitting. **Mitigation:** treat the OSS evaluation as a held-out test set; do not adjust detectors based on OSS scan results before final evaluation.

### External validity

- The benchmark covers Python agents using common frameworks. Findings may not generalise to other languages.
- Vulnerability class definitions may evolve as the agent ecosystem matures.

### Construct validity

- "Vulnerability" is partly judgement-based. We use the Agent Top 10 to ground definitions, but reasonable security professionals may disagree on edge cases.

### Reliability

- LLM-based detection has run-to-run variance. **Mitigation:** report results from `n=5` runs with mean and standard deviation, not single runs.

---

## Statistical Treatment

For LLM-based detection numbers, report:
- Mean precision, recall, F1 across 5 runs
- Standard deviation
- 95% confidence interval (assuming normal distribution; verify with sample)

For static-only mode, results are deterministic — single run sufficient.

---

## Comparison Baseline

Where possible, compare AgentGuard to:

1. **Generic SAST tools** (Bandit, Semgrep) — show they miss agent-specific issues
2. **Manual audit** — measure time taken by an experienced reviewer to find the same issues
3. **OWASP LLM Top 10 checklist** — show our taxonomy is complementary, not redundant

The comparison narrative: *AgentGuard catches things existing tools cannot, in less time than manual audit.*
