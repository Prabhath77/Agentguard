# AgentGuard

A self-validating static security scanner for autonomous AI agents, with an AI-authored exploit prover.

AgentGuard reads AI agent source code (LangChain, AutoGen, CrewAI, Anthropic SDK, and generic frameworks), detects instances of ten agent-specific vulnerability classes (the **Agent Top 10**), and — unlike a conventional static scanner — proves each finding by generating and executing a proof-of-concept exploit inside an isolated sandbox. A finding is only reported as **CONFIRMED** if that exploit actually runs and demonstrates real impact.

## Why this exists

Traditional static analysis tools (Bandit, Semgrep) were built for conventional vulnerabilities and have no concept of agent-specific risks — a tool description that hijacks the model, or two individually safe tools that combine into an exploitable chain. AgentGuard is built specifically to find these, and to prove them rather than just assert them.

---

## 1. What's in this project

```
agentguard/
├── agentguard/              # the scanner itself
│   ├── main.py                # CLI entry point (all commands below)
│   ├── parser.py               # multi-strategy source parser
│   ├── analyzer.py             # LLM semantic analysis (Phase 2)
│   ├── exploit_generator.py    # template + AI-prover exploit generation (Phase 3)
│   ├── sandbox_runner.py       # subprocess sandbox execution
│   ├── docker_sandbox.py       # Docker sandbox execution
│   ├── validator.py            # Phase 3+4 self-validation loop
│   ├── project_scanner.py      # multi-file / folder / zip / GitHub URL scanning
│   ├── reporter.py             # Markdown + JSON report writer (with secret redaction)
│   └── _llm_backend.py         # Gemini / Groq / OpenRouter / OpenAI / Anthropic backends
├── config.py                  # provider selection and all tunables
├── benchmark/                  # the 11-agent labelled benchmark used for evaluation
├── webapp/
│   ├── app.py                   # local web front end (Flask)
│   ├── templates/
│   └── static/
├── requirements.txt
└── reports/                    # scan output lands here (created automatically)
```

---

## 2. Installation

```bash
cd agentguard
pip3 install -r requirements.txt --break-system-packages
```

No provider SDK is required — every backend is spoken over plain HTTP. `pytest`, `bandit`, and `semgrep` are only needed for the tool comparison (`agentguard.main compare`):
```bash
pip3 install bandit semgrep --break-system-packages
```

---

## 3. Configuring an LLM backend

The static detection layer (Phase 1) needs no LLM key at all — add `--no-llm` to any command. The semantic layer (Phase 2) and the AI-authored prover (Phase 3) need one of these free-tier providers.

| Provider | Get a free key | Set it |
|---|---|---|
| **OpenRouter — NVIDIA Nemotron 3 Ultra** *(default)* | https://openrouter.ai/keys | `export OPENROUTER_API_KEY="sk-or-..."` |
| **Gemini** | https://aistudio.google.com/apikey | `export GEMINI_API_KEY="AIza..."` |
| **Groq** | https://console.groq.com/keys | `export GROQ_API_KEY="gsk_..."` |

The provider is **auto-detected** from whichever key is present, checked in this order: OpenRouter → Gemini → Groq. Nemotron 3 Ultra is the default because a controlled comparison against Gemini (same prompts, same targets) found it engaged with every AI-prover request with zero refusals, against a majority-refusal pattern from Gemini on the same targets — full data in the project's evaluation writeup.

To force a specific provider regardless of which keys are set:
```bash
export AGENTGUARD_PROVIDER=gemini      # or: groq, openrouter, openai, anthropic
```
To clear an override and return to auto-detection: `unset AGENTGUARD_PROVIDER`.

**Verify your setup before anything else** — this checks both the LLM connection and which sandbox isolation path will be used:
```bash
python3 -m agentguard.main providers --test
```

---

## 4. Running the backend (command line)

### Quick checks
```bash
python3 -m agentguard.main taxonomy              # print the Agent Top 10
python3 -m agentguard.main providers --test       # confirm LLM + sandbox status
```

### Scanning
```bash
# Static only, no LLM, no validation — fastest, good for a first check
python3 -m agentguard.main scan path/to/agent.py --no-llm

# Full pipeline: static + semantic analysis + sandboxed exploit validation
python3 -m agentguard.main validate path/to/agent.py

# Let the AI-prover attempt each finding BEFORE the deterministic templates
python3 -m agentguard.main validate path/to/agent.py --ai-prover-first

# Scan an entire project folder, a .zip archive, or a public GitHub repo
python3 -m agentguard.main scan path/to/project/
python3 -m agentguard.main scan path/to/project.zip
python3 -m agentguard.main scan https://github.com/owner/repo
```

### Evaluation and reproducibility
```bash
python3 -m agentguard.main evaluate                    # benchmark accuracy (P/R/F1)
python3 -m agentguard.main full-eval --runs 5           # accuracy + determinism together
python3 -m agentguard.main scan-repeat path/to/agent.py --runs 5   # determinism only
python3 -m agentguard.main compare                      # vs Bandit and Semgrep
```

### What a healthy install looks like

| Command | Expected result |
|---|---|
| `providers --test` | `[OK] <provider> responded` |
| `scan benchmark/safe_agent.py --no-llm` | `Findings: 0` |
| `scan-repeat <any target> --runs 5` | `1 unique outcome` |
| `evaluate` | F1 ≈ 0.89–0.90 |

Every CONFIRMED or SUSPECTED finding states plainly which sandbox executed it — `Docker (isolated container)` or `subprocess (resource-limited, NOT filesystem/network isolated)` — printed live and saved permanently in the report, not just claimed.

---

## 5. Running the web front end

```bash
cd webapp
python3 app.py
```
Starts a local server at **http://localhost:5000**. Upload or paste an agent file and submit — it runs the same pipeline as the CLI and returns the same two-section report (deterministic findings kept separate from semantic/AI findings). Whichever provider is configured via the environment variables above is what the web UI uses too.

---

## 6. Verifying Docker sandbox isolation independently

Don't just trust the tool's own claim — check it against Docker's own event log:

```bash
# In one terminal:
docker events --filter image=agentguard-sandbox:latest

# In a second terminal, run any validate/scan command — watch real
# create → attach → start → die → destroy events appear live.
```

To confirm the image itself matches the source:
```bash
docker images agentguard-sandbox
docker history agentguard-sandbox:latest
```

The sandbox image is built from a minimal, non-root Dockerfile:
```dockerfile
FROM python:3.11-slim
RUN useradd -m -u 1000 sandbox
RUN pip install --no-cache-dir requests
USER sandbox
WORKDIR /sandbox
```

---

## 7. Testing against real-world targets

```bash
git clone https://github.com/ReversecLabs/damn-vulnerable-llm-agent.git
python3 -m agentguard.main validate damn-vulnerable-llm-agent/transaction_db.py --ai-prover-first

git clone https://github.com/langchain-ai/langchain-mcp-adapters.git
python3 -m agentguard.main scan langchain-mcp-adapters/langchain_mcp_adapters

git clone https://github.com/crewAIInc/crewAI-tools.git
python3 -m agentguard.main validate crewAI-tools/crewai_tools/tools/code_interpreter_tool --ai-prover-first

git clone https://github.com/microsoft/autogen.git
python3 -m agentguard.main scan autogen/python/packages/autogen-agentchat/src/autogen_agentchat
```

---

## 8. A note on the AI-prover's behaviour

The AI-authored exploit prover asks the active model to write and execute its own proof-of-concept per finding. Its willingness to do so varies by **which model is behind the active provider**, not by anything in AgentGuard's own prompt or pipeline. A model declining to author an exploit is reported as DISMISSED or SUSPECTED, never fabricated as a false CONFIRMED — the deterministic template layer exists specifically so no single model's refusal blocks the tool's core detection ability.

---

## 9. Troubleshooting

- **Gemini model 404s** — the pinned model name may have been retired:
```bash
  curl -s -H "x-goog-api-key: $GEMINI_API_KEY" https://generativelanguage.googleapis.com/v1beta/models | grep '"name"'
```
  then `export GEMINI_MODEL="<a name from that list, without the 'models/' prefix>"`.
- **Rate limits (429 / 503) on any free tier** — handled automatically with retry/backoff; if persistent, switch provider rather than waiting.
- **Docker shows unreachable in `providers --test`** despite being installed — almost always either the daemon isn't running (`sudo systemctl start docker`) or your user isn't in the `docker` group (`sudo usermod -aG docker $USER`, then log out and back in).

## License

Academic project — MSc Cyber Security dissertation, University of Roehampton London.
