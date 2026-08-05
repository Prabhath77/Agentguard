# AgentGuard v0.4

**A self-validating static security scanner for autonomous AI agents.**

MSc Cyber Security research project — University of Roehampton London.

---

## What it does

AgentGuard scans the **source code of an AI agent** — the system prompt, the
tool definitions, the memory layer and the orchestration logic that a developer
writes — and reports security vulnerabilities specific to agentic systems.

It does not assess the model (that is the vendor's responsibility) and it is not
a runtime firewall. It is a **pre-deployment static analysis tool** for the layer
in between, which is the layer the developer actually controls and the layer no
existing scanner covers.

**The core contribution:** AgentGuard does not merely report findings. For every
finding it generates a proof-of-concept exploit, executes that exploit inside an
isolated sandbox, and reports the finding as CONFIRMED only if the exploit
actually fires. Findings whose exploits fail are DISMISSED. This is what removes
the false-positive fatigue that makes conventional SAST output so expensive to
triage.

**New in v0.4:** whole-project scanning. Point AgentGuard at a folder or a zip
and it analyses the entire codebase, including **cross-file capability chains** —
vulnerabilities that exist only in the combination of modules and are invisible
to any scanner that inspects one file at a time.

---

## Quick start

```bash
unzip agentguard_v04.zip
cd agentguard
pip3 install -r requirements.txt --break-system-packages
```

Then get a **free** API key (no credit card required) and export it:

```bash
# Option A — Gemini (default; largest context window)
#   Get a key at https://aistudio.google.com/apikey
export GEMINI_API_KEY="AIza..."

# Option B — Groq (fastest inference)
#   Get a key at https://console.groq.com/keys
export GROQ_API_KEY="gsk_..."
```

AgentGuard auto-detects whichever key is present. Confirm with:

```bash
python3 -m agentguard.main providers --test
```

**AgentGuard also runs entirely without an API key.** Add `--no-llm` to any
command to use the static and sandbox layers only. This mode is fully
deterministic and is what the reported benchmark figures are measured on.

---

## Usage

```bash
# The vulnerability taxonomy
python3 -m agentguard.main taxonomy

# Scan a single file, a project folder, or a zip — the same command handles all three
python3 -m agentguard.main scan benchmark/vuln_06_code_exec.py --no-llm
python3 -m agentguard.main scan benchmark_projects/01_fintech_support_agent --no-llm
python3 -m agentguard.main scan /path/to/client_handover.zip --no-llm

# Full pipeline: scan + generate exploits + run them in the sandbox
python3 -m agentguard.main validate benchmark/vuln_06_code_exec.py --no-llm
python3 -m agentguard.main validate benchmark_projects/02_devops_assistant --no-llm

# Add automated remediation with verified patches
python3 -m agentguard.main validate-full benchmark/vuln_06_code_exec.py

# Benchmarks
python3 -m agentguard.main evaluate              # 9 single-file agents
python3 -m agentguard.main evaluate --projects   # 5 multi-file projects

# Show / test the active free LLM backend
python3 -m agentguard.main providers --test
```

Reports are written to `reports/` in both Markdown and JSON.

---

## Report structure

Every report — single file, folder, or zip, in Markdown, JSON, and the web UI —
separates findings into two clearly labelled sections:

- **Section 1 — Static Analysis.** Deterministic AST and pattern-based
  detectors. No API key required, fully reproducible. This is what the
  benchmark figures below are measured on.
- **Section 2 — Gemini AI Analysis.** The LLM reasoning layer. For each issue
  the model states what is wrong, proposes a fix with replacement code where
  applicable, and reports a confidence level (High / Medium / Low). These are
  expert-review suggestions to verify, not proven facts — which is why they are
  kept visually and structurally distinct from the deterministic findings.

Section 2 populates only when an API key is set and the LLM layer is enabled
(omit `--no-llm`, or tick the box in the web UI). With `--no-llm` the report
still renders Section 2, noting that the AI layer was disabled.

---

## Results

**Single-file benchmark** — 9 agents, deterministic across repeated runs:

| Metric | Value |
|--------|-------|
| Precision | 0.857 |
| Recall | 0.923 |
| **F1** | **0.889** |
| True positives | 12 |
| False positives | 2 |
| False negatives | 1 |
| False positives on the safe agent | 0 |

**Multi-file project benchmark** — 5 realistic projects:

| Metric | Value |
|--------|-------|
| Precision | 1.000 |
| Recall | 0.750 |
| **F1** | **0.857** |
| Cross-file chains detected | 3 / 3 |
| Negative control clean | 1 / 1 |

The three project-benchmark false negatives are documented detector gaps, not
scoring artefacts — see `benchmark_projects/project_ground_truth.json`.

---

## The Agent Top 10

The project's vulnerability taxonomy, mapped to MITRE ATLAS and the OWASP LLM
Top 10.

| ID | Vulnerability |
|----|---------------|
| AGT-001 | Excessive Tool Permissions |
| AGT-002 | Prompt Injection via Tool Description |
| AGT-003 | System Prompt Leakage |
| AGT-004 | Unsafe Tool Chaining |
| AGT-005 | Memory Poisoning |
| AGT-006 | Missing Tool Input Validation |
| AGT-007 | Hardcoded Secrets in Agent Configuration |
| AGT-008 | Unsafe Code Execution Capability |
| AGT-009 | Missing Output Filtering |
| AGT-010 | Excessive Agency Without Confirmation |

---

## How it works

```
Agent source (file | folder | zip)
        |
   PHASE 1  Static analysis        AST parsing + 11 detectors
        |
   PHASE 2  LLM reasoning          semantic review of prompts and tools
        |
   PHASE 3  Exploit generation     templates, with an LLM fallback
        |
   PHASE 4  Sandboxed validation   run the exploit; confirm only if it fires
        |
   CONFIRMED  /  SUSPECTED  /  DISMISSED
```

At project scope an additional pass runs after Phase 1: every tool in every file
is classified by capability, and the resulting capability set is checked for
combinations that produce an attack outcome using tools drawn from **different
files**. A `read_customer_records()` in `tools/accounts.py` is harmless. A
`send_email()` in `tools/notifications.py` is harmless. Together they are a
data-exfiltration chain, and neither file review would ever surface it.

---

## Project layout

```
agentguard/
  agentguard/
    taxonomy.py           the Agent Top 10
    parser.py             source -> AgentManifest (AST)
    analyzer.py           11 static detectors + LLM analysis
    graph_builder.py      capability classification, attack paths
    project_scanner.py    NEW - folder/zip scanning, cross-file chains
    exploit_generator.py  exploit templates + dependency-stub shim
    stateful_exploit.py   multi-turn exploits (memory poisoning)
    sandbox_runner.py     subprocess / Docker dispatch
    docker_sandbox.py     hardened container execution
    validator.py          three-bucket verdict logic
    remediation.py        patch generation and verification
    reporter.py           Markdown and JSON reports
    _llm_backend.py       NEW - Gemini / Groq / OpenAI / Anthropic over HTTP
    main.py               CLI
  benchmark/              9 single-file agents + ground truth
  benchmark_projects/     NEW - 5 multi-file projects + ground truth
  docs/                   methodology, results, release notes
  config.py               provider auto-detection and scanner settings
```

---

## Testing

```bash
# Provider contract tests — no network, no API key required
python3 tests/test_providers_offline.py

# Live connectivity check — needs a real key on a networked machine
python3 -m agentguard.main providers --test
```

The offline suite (36 checks) verifies that each backend builds the correct
endpoint URL, uses the correct authentication scheme, matches each provider's
documented request schema, pins `temperature` to 0.0, parses each provider's
distinct response shape, and handles missing keys, rate limits and auth errors
correctly. It does this by substituting the HTTP layer, so it runs anywhere.

It cannot prove a provider accepts the request in production — only a live key
settles that, which is what `providers --test` is for.

---

## If the Gemini model 404s

Google renames and retires Gemini model IDs every few months — faster than this
README can track. If `providers --test` (or any scan with an API key set) fails
with `404 ... models/gemini-...-flash:generateContent`, the model name baked
into `config.py` has been retired. This is not a key problem.

Fix it by listing the models your own key currently has access to, and picking
one from that list:

```bash
curl -s -H "x-goog-api-key: $GEMINI_API_KEY" \
  https://generativelanguage.googleapis.com/v1beta/models | grep '"name"'
```

Then point AgentGuard at whichever name is current (drop the `models/` prefix):

```bash
export GEMINI_MODEL="gemini-3.1-flash-lite"     # example — use what the list showed you
python3 -m agentguard.main providers --test
```

No code edit needed — `GEMINI_MODEL` is read from the environment the same way
`GEMINI_API_KEY` is. If Gemini keeps giving you trouble, switch to Groq entirely
instead of chasing model names:

```bash
export AGENTGUARD_PROVIDER=groq
export GROQ_API_KEY="gsk_..."
python3 -m agentguard.main providers --test
```

---

## Web UI

For a browser-based alternative to the CLI — upload a file, a zip, or a whole
folder, and get a scan report you can download.

```bash
pip3 install flask --break-system-packages
cd webapp
python3 app.py
```

Open **http://localhost:5000**. Three upload options:

- **Single file (.py)** — one agent script
- **Zip archive** — a whole project, zipped (the client-handover scenario)
- **Whole folder** — pick a folder directly in the browser; every file inside
  it (subfolders included) is scanned as one project

Findings render in the browser with severity colour-coding, and cross-file
capability chains are called out in their own section above the rest. Download
buttons produce the same Markdown and JSON reports the CLI writes — the web UI
is a thin front end over `agentguard.project_scanner.scan_target()`, not a
separate implementation, so it can never disagree with the CLI about what
counts as a finding.

Uploaded code is deleted from disk immediately after the scan completes; only
the generated report is kept, and only until you download it.

**Run this on localhost, or behind your own authentication if you expose it
further.** It accepts arbitrary uploaded code and — same as the CLI — that
code gets analysed and its findings' exploits get executed in a sandbox as
part of the normal pipeline. The sandbox is hardened, but "hardened" is not
the same claim as "safe to put on the open internet." Treat it as a local
analyst tool.

---

## Notes on the free providers

Both supported free tiers are ample for this workload — a full benchmark run
makes only tens of API calls.

- **Gemini** (default) offers the larger context window, which suits
  whole-project analysis. Note that Google's free tier permits prompts and
  responses to be used for model improvement; that is fine for the synthetic
  benchmark agents in this repository, but real client code should be scanned
  with `--no-llm` or on a paid tier.
- **Groq** is markedly faster and runs open-weight models. It speaks the
  OpenAI protocol, so any OpenAI-compatible endpoint works by setting
  `OPENAI_BASE_URL`.

Agent frameworks are deliberately **not** dependencies. AgentGuard analyses code
that imports `anthropic`, `langchain` or a client's private packages without
having them installed, because the sandbox stubs absent modules at import time.
