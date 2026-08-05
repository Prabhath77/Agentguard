# AgentGuard Benchmark Results

This document records the measured performance of AgentGuard v0.2 on its built-in benchmark. All numbers are reproducible — running the benchmark suite produces the same results every time.

---

## Headline Numbers

Across 10 consecutive runs on the full 8-file benchmark, with self-validation enabled and templates only (no LLM):

| Metric | Value |
|--------|------|
| **Precision (CONFIRMED only)** | **0.846** |
| **Recall (CONFIRMED only)** | **0.917** |
| **F1 Score** | **0.880** |
| **Determinism** | 100% (1 unique outcome across 10 runs) |
| **Time per full benchmark** | ~17 seconds |
| **False positives on safe_agent.py** | 0 |

---

## Per-File Breakdown

| File | Expected vulns | Confirmed by exploit | FP | FN |
|------|---------------|---------------------|-----|-----|
| vuln_01_overprivileged.py | AGT-001, AGT-006, AGT-008 | AGT-001, AGT-004, AGT-006, AGT-008 | 1 | 0 |
| vuln_02_prompt_injection.py | AGT-002 | AGT-002 | 0 | 0 |
| vuln_03_system_leak.py | AGT-003, AGT-007 | AGT-007 | 0 | 1 |
| vuln_04_tool_chain.py | AGT-004 | AGT-004 | 0 | 0 |
| vuln_05_secrets.py | AGT-007 | AGT-007 | 0 | 0 |
| vuln_06_code_exec.py | AGT-006, AGT-008 | AGT-004, AGT-006, AGT-008 | 1 | 0 |
| vuln_07_no_validation.py | AGT-006, AGT-009 | AGT-006, AGT-009 | 0 | 0 |
| safe_agent.py | (none) | (none) | 0 | 0 |
| **Totals** | **12** | **11 confirmed** | **2** | **1** |

---

## Analysis Of The 2 False Positives

Both "false positives" are arguably real findings:

**AGT-004 in vuln_01_overprivileged.py** — The capability graph correctly identified that this agent has both READ_LOCAL (filesystem read) and WRITE_EXTERNAL (subprocess output) capabilities. This is a real data exfiltration chain — just not the primary vulnerability the file was designed to demonstrate.

**AGT-004 in vuln_06_code_exec.py** — Similar story. The agent exposes calculate, run_python, and system_info which together form a clear privilege escalation chain. Again, real finding; just not what the file was originally designed for.

The takeaway: AgentGuard found additional real vulnerabilities the benchmark wasn't specifically testing for. In a research context this is good news — it suggests the scanner generalises beyond the specific cases it was tuned for.

---

## Analysis Of The 1 False Negative

**AGT-003 in vuln_03_system_leak.py** — The system prompt does contain sensitive content (an API key, phone number, and database credentials). The static analyzer correctly flags it. But the exploit template's regex didn't match the natural-language phrasing of the prompt ("Our backend API key is sk-acme-..." rather than "api_key: sk-acme-..."). The finding is preserved as SUSPECTED — not lost.

---

## Stability

Across 10 consecutive runs, the benchmark produced exactly one unique outcome (TP=11, FP=2, FN=1). Standard deviation is zero. Time variance: min 17.2s, max 18.0s, average 17.5s.

---

## How To Reproduce

```bash
cd agentguard
pip install -r requirements.txt
python -m agentguard.main evaluate
```

Expected output ends with: `Precision: 0.846  Recall: 0.917  F1: 0.880`

---

# v0.4 Results

## Single-file benchmark (unchanged from v0.3.1)

9 agents, `--no-llm`, verified deterministic across 3 consecutive runs.

| Metric | Value |
|--------|-------|
| Precision | 0.857 |
| Recall | 0.923 |
| F1 | 0.889 |
| True positives | 12 |
| False positives | 2 |
| False negatives | 1 |

Confirmed unchanged after two significant architectural changes in v0.4 (the
provider swap and the dependency-stub shim), which is the point of retaining the
benchmark as a regression gate.

## Multi-file project benchmark (new in v0.4)

5 realistic multi-file agent projects.

| Metric | Value |
|--------|-------|
| Precision | 1.000 |
| Recall | 0.750 |
| F1 | 0.857 |
| True positives | 9 |
| False positives | 0 |
| False negatives | 3 |
| Cross-file chains detected | 3 / 3 |
| Negative controls clean | 1 / 1 |

Per-project breakdown:

| Project | Expected | Found | TP | FP | FN | Chain |
|---------|----------|-------|----|----|----|-------|
| 01_fintech_support_agent | (none per-file) | (none) | 0 | 0 | 0 | 1/1 |
| 02_devops_assistant | 001, 004, 006, 007, 008 | all five | 5 | 0 | 0 | 1/1 |
| 03_healthcare_triage_agent | 003, 005, 006, 007 | 003, 006, 007 | 3 | 0 | 1 | 0/0 |
| 04_ecommerce_agent | 004, 006, 010 | 004 | 1 | 0 | 2 | 1/1 |
| 05_research_assistant_safe | (clean) | (clean) | 0 | 0 | 0 | 0/0 |

Perfect precision across the project corpus: AgentGuard raised no finding that
was not genuinely present. Recall is limited by three documented detector gaps
(see V04_RELEASE_NOTES.md, Known limitations).

### Note on project 01

`01_fintech_support_agent` has an intentionally empty `expected_findings` list.
Every file in it is individually clean; the only vulnerability is the cross-file
data-exfiltration chain. Any scanner operating one file at a time scores zero on
this project by construction, which makes it the clearest available
demonstration of what project-level capability analysis contributes.
