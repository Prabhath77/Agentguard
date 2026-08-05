# AgentGuard v0.4 — Quick Start & Demo Script

A 10-minute path from a clean Ubuntu VM to a working demonstration.

---

## 1. Install (2 minutes)

```bash
unzip agentguard_v04.zip
cd agentguard
pip3 install -r requirements.txt --break-system-packages
```

Only three small packages install. No agent framework SDKs are needed.

Verify the install immediately — this needs no API key and no network:

```bash
python3 tests/test_providers_offline.py
```

Expect `36 passed, 0 failed`.

---

## 2. Get a free API key (2 minutes, optional)

Everything below runs with `--no-llm` and no key at all. Add a key only if you
want the LLM reasoning layer.

**Gemini** (default) — https://aistudio.google.com/apikey

```bash
export GEMINI_API_KEY="AIza..."
```

**Groq** (alternative, faster) — https://console.groq.com/keys

```bash
export GROQ_API_KEY="gsk_..."
```

Verify:

```bash
python3 -m agentguard.main providers --test
```

To make the key permanent, append the `export` line to `~/.bashrc`.

---

## 3. The demo sequence

Run these in order and screenshot each into a `supervisor_demo/` folder.

### Demo 1 — The research contribution

```bash
python3 -m agentguard.main taxonomy
```

Prints the Agent Top 10 with MITRE ATLAS and OWASP LLM mappings. This is the
taxonomy the whole tool is built around.

### Demo 2 — Single-file static scan

```bash
python3 -m agentguard.main scan benchmark/vuln_06_code_exec.py --no-llm
```

Finds 8 critical issues in a deliberately vulnerable agent. Fast, no API cost.

### Demo 3 — Self-validation, the core novelty

```bash
python3 -m agentguard.main validate benchmark/vuln_06_code_exec.py --no-llm
```

Watch the pipeline generate an exploit per finding, execute each in the sandbox,
and sort the results into CONFIRMED / SUSPECTED / DISMISSED. This is what
separates AgentGuard from a conventional SAST tool: nothing is reported as
confirmed unless the exploit actually fired.

### Demo 4 — Multi-turn stateful exploitation

```bash
python3 -m agentguard.main validate benchmark/vuln_08_memory_poison.py --no-llm
```

Memory poisoning cannot be proven in a single call. The exploit plants content
through one tool and triggers it through another on a later turn.

### Demo 5 — Whole-project scanning and cross-file chains  *(v0.4)*

```bash
python3 -m agentguard.main scan benchmark_projects/01_fintech_support_agent --no-llm
```

**This is the strongest demonstration.** Every individual file in this project
is clean. `tools/accounts.py` only reads. `tools/notifications.py` only sends.
AgentGuard reports a CRITICAL data-exfiltration chain because those two
capabilities together give an injected agent a way out with the data — a finding
no single-file scanner can produce.

### Demo 6 — Scanning a client handover zip  *(v0.4)*

```bash
cd benchmark_projects && zip -qr /tmp/handover.zip 02_devops_assistant && cd ..
python3 -m agentguard.main scan /tmp/handover.zip --no-llm
```

The realistic engagement workflow: a client sends an archive, AgentGuard
extracts it safely (with path-traversal protection), walks the tree, and
assesses the whole codebase. Note that `config/secrets.py` is flagged even
though it defines no tools and no system prompt — a scanner pointed only at the
"agent file" would miss those four hardcoded credentials entirely.

### Demo 7 — The negative control

```bash
python3 -m agentguard.main scan benchmark_projects/05_research_assistant_safe --no-llm
```

A well-built multi-file agent. Zero findings, zero chains. Demonstrates the
scanner is not simply flagging everything it sees.

### Demo 8 — The headline metrics

```bash
python3 -m agentguard.main evaluate
python3 -m agentguard.main evaluate --projects
```

Single-file benchmark: **P=0.857, R=0.923, F1=0.889**
Project benchmark: **P=1.000, R=0.750, F1=0.857**, 3/3 cross-file chains,
negative control clean.

Both are deterministic in `--no-llm` mode — re-run them and the numbers do not
move, which is what makes them citable in the dissertation.

---

## Talking points for the supervisor meeting

**What is being scanned.** The agent's own source code: system prompt, tool
definitions, memory layer, orchestration. Not the model — that is closed-weights
and the vendor's problem. Not the runtime — that is the territory of products
like Lakera. The layer in between is the one the developer controls and the one
nothing currently covers.

**Why validation matters.** Conventional SAST reports possibilities. AgentGuard
reports proven facts. A CONFIRMED finding comes with the exploit that produced
it, so a developer can reproduce the issue rather than argue about it.

**Why project scanning matters.** Real engagements deliver repositories, not
files. More importantly, the most dangerous agent vulnerabilities are emergent:
they exist in the combination of capabilities, not in any one function. That
class of vulnerability is undetectable by construction if you analyse one file
at a time.

**Honest limitations.** The project benchmark carries three false negatives, all
documented in `benchmark_projects/project_ground_truth.json`: memory poisoning
is missed when the store is a separate module from the orchestrator, and
financial actions lacking a confirmation gate are not yet flagged statically.
The single-file benchmark carries one known false negative (AGT-003 in
`vuln_03`) and two false positives. These are recorded rather than tuned away.

### Demo 9 — The web UI  *(v0.4)*

```bash
pip3 install flask --break-system-packages
cd webapp && python3 app.py
```

Open `http://localhost:5000` in the VM's browser. Upload the same fintech
project used in Demo 5 as a folder, and watch the identical cross-file chain
render in the browser with a downloadable report. Same engine underneath the
CLI and the web UI — useful to say out loud in the meeting.

---

## Troubleshooting

**`ModuleNotFoundError: No module named 'requests'`**
`pip3 install requests --break-system-packages`

**`No API key set for provider`**
Either export a key (step 2) or add `--no-llm`.

**Rate-limited (HTTP 429)**
Free tiers have per-minute caps. The backend retries with exponential backoff
automatically; if it persists, switch provider with
`export AGENTGUARD_PROVIDER=groq` or fall back to `--no-llm`.

**Docker not installed**
Optional. The sandbox falls back to a resource-limited subprocess and all
benchmark figures above are reproducible without Docker.
