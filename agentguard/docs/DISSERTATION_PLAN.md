# Dissertation Plan — AgentGuard

**Working Title:** *AgentGuard: A Static Analysis Framework for Security Assessment of Autonomous AI Agents*

**Programme:** MSc Cyber Security, University of Roehampton London

---

## Research Question

*Can static analysis combined with LLM-assisted reasoning reliably detect security vulnerabilities in AI agent codebases at a precision and recall sufficient for production use?*

---

## Contribution

This dissertation makes three contributions:

1. **The Agent Top 10** — a vulnerability taxonomy specifically for autonomous AI agents, mapped to MITRE ATLAS and OWASP LLM Top 10
2. **AgentGuard** — a working open-source static analysis tool implementing the taxonomy
3. **A benchmark dataset** — labelled vulnerable agents enabling reproducible evaluation of agent security tools

---

## Chapter Structure

### Chapter 1 — Introduction (8–10 pages)

- 1.1 Context: rapid adoption of AI agents in industry
- 1.2 Problem: agents introduce new attack surface unaddressed by traditional AppSec
- 1.3 Research question and objectives
- 1.4 Scope (what's in / out)
- 1.5 Contributions
- 1.6 Thesis structure

### Chapter 2 — Literature Review (15–20 pages)

- 2.1 Traditional application security (AppSec) — SAST, DAST, IAST
- 2.2 LLM security research — prompt injection, jailbreaking, OWASP LLM Top 10
- 2.3 Agentic AI systems — LangChain, AutoGen, CrewAI, Anthropic SDK tool use
- 2.4 MITRE ATLAS framework for adversarial ML
- 2.5 Existing AI security tooling — Lakera, Protect AI, HiddenLayer, Robust Intelligence (analysis of what they cover and what they miss)
- 2.6 Gap analysis — no existing tool specifically targets autonomous agent codebases

### Chapter 3 — Methodology (10–12 pages)

- 3.1 Research design — design science approach
- 3.2 Threat model — what attackers we defend against
- 3.3 The Agent Top 10 — taxonomy development methodology
- 3.4 Detection methodology — hybrid static analysis + LLM reasoning
- 3.5 Benchmark construction — how vulnerable test agents were designed
- 3.6 Evaluation methodology — precision, recall, F1
- 3.7 Ethical considerations

### Chapter 4 — Design and Implementation (15–20 pages)

- 4.1 Architecture overview
- 4.2 The Parser — AST-based component extraction
- 4.3 Static detectors — deterministic rules (secrets, code exec, validation gaps)
- 4.4 The Capability Graph — modelling tool privilege escalation paths
- 4.5 LLM Analyzer — prompt engineering for semantic vulnerability detection
- 4.6 Reporter — pentest-style output generation
- 4.7 Implementation choices and trade-offs

### Chapter 5 — Evaluation (15–18 pages)

- 5.1 Benchmark dataset description
- 5.2 Static-only baseline results
- 5.3 Static + LLM combined results
- 5.4 Per-vulnerability-class analysis (where the tool excels and struggles)
- 5.5 False positive analysis
- 5.6 Real-world evaluation against open source agents
- 5.7 Comparison to manual audit (time + accuracy)
- 5.8 Threats to validity

### Chapter 6 — Discussion (8–10 pages)

- 6.1 Implications for agent developers
- 6.2 Implications for security practitioners
- 6.3 Implications for the AI agent ecosystem
- 6.4 Limitations of the current approach
- 6.5 Future research directions

### Chapter 7 — Conclusion (3–5 pages)

- 7.1 Summary of contributions
- 7.2 Answer to research question
- 7.3 Future work

### References & Appendices

- Appendix A: Full Agent Top 10 specification
- Appendix B: Benchmark agent listings
- Appendix C: Detection prompt templates
- Appendix D: Per-finding evaluation results

---

## 14-Week Timeline

| Week | Activity | Deliverable |
|------|----------|------------|
| 1 | Literature review starts; ethics application | Ethics form submitted |
| 2 | Literature review continues; project setup | Lit review draft 1 |
| 3 | Implement parser + static detectors | Working static scanner |
| 4 | Implement capability graph + attack paths | Graph builder complete |
| 5 | Implement LLM analyzer | Full pipeline working |
| 6 | Build benchmark dataset (20+ agents) | Benchmark + ground truth |
| 7 | Run benchmark evaluation; iterate | Initial precision/recall numbers |
| 8 | Real-world testing on OSS agents | Real-world findings |
| 9 | Comparative analysis vs manual audit | Comparison table |
| 10 | Write Chapters 1–2 | Intro + Lit Review draft |
| 11 | Write Chapters 3–4 | Methodology + Implementation draft |
| 12 | Write Chapters 5–6 | Evaluation + Discussion draft |
| 13 | Final integration; supervisor review | Full draft |
| 14 | Polish; submit | **Dissertation submitted** |

---

## Test Subjects

### Tier 1 — Controlled benchmark (your own)

- 7 deliberately vulnerable agents (in `benchmark/`)
- 1 negative control (safe_agent.py)
- Aim to extend to **20+ agents** covering all 10 vulnerability classes with multiple variations each

### Tier 2 — Real-world open-source agents

| Source | What to scan |
|--------|-------------|
| github.com/langchain-ai/langchain/tree/master/cookbook | LangChain example agents |
| github.com/microsoft/autogen | AutoGen example agents |
| github.com/joaomdmoura/crewAI-examples | CrewAI examples |
| github.com/anthropics/anthropic-cookbook | Anthropic SDK examples |
| github.com/openai/openai-cookbook | OpenAI agent examples |
| huggingface.co/spaces (filter: agentic) | Public Hugging Face agent demos |

For each, document:
- Findings from AgentGuard
- Manual verification (true / false / arguable)
- Responsible disclosure if real vulnerabilities found

### Tier 3 — Synthetic agents from LLM generation

Use Claude/GPT-4 to *generate* agents from natural language descriptions, then scan those. Tests robustness against unusual coding styles.

---

## Evaluation Targets

| Metric | MSc Target | Stretch |
|--------|-----------|---------|
| Static-only precision | ≥ 0.80 | ≥ 0.90 |
| Static-only recall | ≥ 0.80 | ≥ 0.90 |
| Static + LLM precision | ≥ 0.85 | ≥ 0.93 |
| Static + LLM recall | ≥ 0.85 | ≥ 0.95 |
| F1 | ≥ 0.85 | ≥ 0.92 |
| Time per scan | ≤ 60s | ≤ 30s |

---

## Ethics

- All vulnerable agents are constructed in-house for research; no real systems are attacked
- Real-world OSS agent scanning follows responsible disclosure: any real vulnerabilities found are reported to maintainers privately before publication
- No personally identifiable information (PII) is collected
- Results are reproducible and the dataset is published openly

---

## Path To Publication

After MSc submission:

1. **Open source release** on GitHub with permissive licence (MIT/Apache 2.0)
2. **Workshop paper** to AISec or DLS — fast path to dissemination
3. **Conference paper** to USENIX Security or IEEE S&P — the prestige path
4. **OWASP integration** — propose Agent Top 10 as an OWASP project

---

## Path To Startup

| Milestone | What | Time |
|-----------|------|------|
| MSc submitted | Working scanner + benchmark + paper | Month 4 |
| Public GitHub launch | Open source MVP, build community | Month 5 |
| Design partners | 5 enterprise pilots (free) | Month 8 |
| Pre-seed | Demo + LOIs to pre-seed investors | Month 10 |
| Seed | £1–2M raise, hire 2-3 engineers | Month 12 |
| Commercial product | SaaS platform, paid customers | Month 18 |
| Series A | £8–15M, scale GTM | Month 30 |

---

## ADDENDUM — The Self-Validation Loop (Phases 3 + 4)

This addendum was added after the architecture evolved to include
sandboxed exploit validation — the core differentiator of AgentGuard.

### Updated Research Question

*Can a static analysis scanner that auto-generates and sandbox-executes
proof-of-concept exploits achieve materially lower false-positive rates
than pure-static approaches, without sacrificing recall?*

### Two New Contributions

In addition to the original three:

4. **The Auto-Exploitation Framework** — a deterministic-first, LLM-fallback
   exploit generator that produces real working PoC code for each finding
5. **The Three-Bucket Output System** — CONFIRMED / SUSPECTED / DISMISSED,
   with confidence gradients and differential testing

### Updated Evaluation Numbers

| Configuration | Precision | Recall | F1 | Determinism |
|---------------|-----------|--------|----|----|
| Static-only | 0.800 | 1.000 | 0.889 | 100% |
| Static + Validation (CONFIRMED only) | 0.846 | 0.917 | 0.880 | 100% |
| Hybrid (CONFIRMED + SUSPECTED) | (estimated 0.75) | (estimated 1.000) | (estimated 0.857) | 100% |

The CONFIRMED-only configuration represents the **zero-noise alert
stream** — the value proposition for security teams.

### Updated Chapter 4 Sections

- 4.6 The Exploit Generator (Phase 3)
  - 4.6.1 Template-based exploits
  - 4.6.2 LLM-based exploit generation for novel cases
  - 4.6.3 Adaptive retry with failure-informed prompts
- 4.7 The Sandbox Runner (Phase 4)
  - 4.7.1 Defence in depth — eight isolation layers
  - 4.7.2 Structured success flags and confidence scoring
  - 4.7.3 Differential testing methodology
- 4.8 The Validator — bucket assignment logic

### New Threats To Validity

- LLM exploit generation introduces non-determinism IF used. Templates
  are fully deterministic; LLM fallback should be reported separately
  with `n=5` runs and standard deviation.
- Sandbox escape risk — mitigated by defence in depth, but should be
  assessed in dissertation
- Coverage gap — exploit templates do not yet cover every vulnerability
  class (e.g. AGT-005 memory poisoning has no template yet)
