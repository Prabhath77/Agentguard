# AgentGuard v0.4 — Release Notes

Two substantial changes over v0.3.1, plus one architectural fix that emerged
from testing and turned out to matter more than either.

---

## 1. Free LLM providers

v0.3.1 required a paid Anthropic API key. v0.4 defaults to free providers and
requires no payment card.

| Provider | Cost | Notes |
|----------|------|-------|
| **Gemini** (default) | Free | Largest context window; suits whole-project analysis |
| **Groq** | Free | Fastest inference; open-weight models |
| OpenAI | Paid | Any OpenAI-compatible endpoint via `OPENAI_BASE_URL` |
| Anthropic | Paid | The original v0.3 backend, retained |

The provider is auto-detected from whichever key is exported, so setup is a
single `export`. `AGENTGUARD_PROVIDER` forces a specific backend.

**Implementation note.** All four providers are spoken over plain HTTP through
`requests` rather than through provider SDKs. This was a deliberate choice: SDK
version drift is the most common cause of a research artefact failing to run on
someone else's machine two years later, and an examiner reproducing this work
should not have to resolve a dependency conflict to do so.

Determinism is preserved by pinning `temperature = 0.0` on every provider.

---

## 2. Whole-project scanning

`scan` and `validate` now accept a **single file, a project folder, or a zip
archive**. Single-file behaviour is unchanged; the new paths are additive.

```bash
python3 -m agentguard.main scan agent.py            # unchanged
python3 -m agentguard.main scan ./my_project/       # new
python3 -m agentguard.main scan handover.zip        # new
```

Zip extraction is guarded against path traversal ("zip slip"): archive members
resolving outside the extraction root are refused rather than written.

### Cross-file capability chains

The substantive contribution of this release. After per-file analysis, every
tool across every file is classified by capability, and the resulting capability
set is tested for combinations that produce an attack outcome using tools drawn
from **different files**.

```
tools/accounts.py       read_customer_records()   -> READ_LOCAL
tools/notifications.py  send_email()              -> WRITE_EXTERNAL
                                                     ------------------
                                                     DATA_EXFILTRATION
```

Neither file contains a vulnerability. Neither would fail code review. The
vulnerability exists only in the combination, and is therefore undetectable by
construction for any tool that analyses one file at a time.

Chains contained within a single file are excluded here, since the existing
single-file analyser already reports them; only genuinely cross-file chains are
raised, which prevents double-counting.

A subtlety worth recording: provider selection prefers a tool from a file not
yet used in the chain. Choosing the first available provider for each capability
caused a real miss during development — an account-takeover chain was suppressed
because a same-file provider happened to sort first, even though a cross-file
provider existed.

---

## 3. Dependency stubbing (the fix that mattered)

Discovered while re-running the benchmark after removing the Anthropic SDK:
every sandboxed exploit failed instantly with `No module named 'anthropic'`, and
the benchmark F1 collapsed from 0.889 to 0.267. Every finding was being
DISMISSED because the exploit could not load the agent module at all.

The naive fix — reinstate the SDK as a dependency — would have papered over a
real limitation. **An analyst cannot install a client's entire dependency tree in
order to scan their code**, and for untrusted client code it would be unwise to
try.

The sandbox now registers a last-resort meta-path finder that stubs any module
that is genuinely absent. Real installed packages are unaffected, because the
finder is *appended* to `sys.meta_path` and is consulted only after every normal
finder has failed.

Two details were necessary to make this work on real agent code:

- **Stubs are classes, not instances.** Agent code frequently subclasses
  framework types (`class Config(BaseModel)`), and an instance used as a base
  raises a metaclass conflict. Stubs are created through a metaclass derived
  from `type`, so subclassing behaves normally.
- **Stubs act as identity decorators.** `@tool` imported from a stubbed
  framework must return the original function; otherwise the tool under test is
  replaced by a stub and the exploit calls nothing. A stub invoked with a single
  callable argument returns that argument unchanged.

The shim is applied centrally in `sandbox_runner.run_exploit()` rather than in
individual exploit templates, so it also covers LLM-generated exploits, which
are written at runtime and cannot be patched in advance.

This restored the benchmark to exactly F1 = 0.889 and — more usefully — means
AgentGuard can now assess third-party code without installing its dependencies.

---

## 4. New test corpus: 5 multi-file projects

`benchmark_projects/` adds five realistic multi-file agent applications with
ground truth in `project_ground_truth.json`.

| Project | Framework | Tests |
|---------|-----------|-------|
| `01_fintech_support_agent` | Anthropic SDK | Cross-file exfiltration where **no single file is vulnerable** |
| `02_devops_assistant` | custom | Secrets in a module with no tools; RCE; cross-file fetch-to-execute |
| `03_healthcare_triage_agent` | custom | Prompt leakage, SQL injection, memory poisoning across packages |
| `04_ecommerce_agent` | LangChain | Framework detection on a multi-file project; account-takeover chain |
| `05_research_assistant_safe` | custom | **Negative control** — correctly built, must yield zero findings |

Project 1 is the methodologically important one: its `expected_findings` list is
deliberately empty. A single-file scanner scores zero on it by definition, which
makes it a clean demonstration of what project-level analysis adds.

---

## 5. Other changes

- New `providers` command shows the active backend and tests connectivity
  (`--test`).
- New `evaluate --projects` runs the multi-file benchmark.
- Capability keyword coverage widened for real-world naming (`issue_refund`,
  `update_payment_method`, `process_payment`, `reset_password` and similar).
  The previous patterns required trailing underscores and missed common verb
  ordering.
- Per-file and cross-file findings are scored on separate axes in the project
  benchmark, so a cross-file chain is not simultaneously counted as a per-file
  false positive.

---

## Results

**Single-file benchmark** (9 agents, `--no-llm`, deterministic across 3+ runs):

| Metric | v0.3.1 | v0.4 |
|--------|--------|------|
| Precision | 0.857 | 0.857 |
| Recall | 0.923 | 0.923 |
| F1 | 0.889 | **0.889** |

No regression. The identical figures were verified after the provider swap and
the dependency-shim change.

**Project benchmark** (5 multi-file projects, new in v0.4):

| Metric | Value |
|--------|-------|
| Precision | 1.000 |
| Recall | 0.750 |
| F1 | 0.857 |
| Cross-file chains detected | 3 / 3 |
| Negative controls clean | 1 / 1 |

---

## Known limitations

Recorded rather than tuned away, and each is a candidate for future work.

1. **AGT-005 missed when memory is a separate module.** In
   `03_healthcare_triage_agent` the memory-poisoning detector does not fire
   because the store lives in `memory/store.py` rather than alongside the
   orchestrator. The detector's heuristics are file-local.
2. **AGT-010 not detected statically.** Financial or otherwise consequential
   actions lacking a confirmation gate are currently surfaced only through
   capability-chain analysis, not by a dedicated static detector.
3. **AGT-003 false negative in `vuln_03`** carried over from v0.3.1.
4. **Cross-file chains are reported statically, not sandbox-confirmed.** Proving
   a chain end-to-end would require instantiating the whole application rather
   than importing a single tool. The chains are therefore reported with 0.85
   confidence rather than as CONFIRMED.

---

## v0.4.2 — Broader tool recognition + SQL injection detection

Prompted by held-out testing against the WithSecure/Reversec **Damn Vulnerable
LLM Agent (DVLA)** — a third-party LangChain agent neither the tool nor its
benchmark had seen.

**The problem found by real testing.** The initial DVLA scan detected 0 tools
and 0 agent files. Cause: the parser recognised only the `@tool` decorator,
while DVLA (like much real LangChain code) declares tools with the
`Tool(name=, func=)` constructor. With no tools parsed, every agent-specific
detector was silently skipped, and only the generic secret scanner fired.

**Fixes:**

1. **Comprehensive tool recognition.** `parse_agent` now detects tools three
   ways: (1) decorator forms, (2) constructor forms — `Tool(...)`,
   `StructuredTool(...)`, `Tool.from_function(...)` — linked back to their
   implementing function, and (3) a broadened structural fallback covering
   every framework, not just anthropic/custom. The tool no longer misses agent
   code merely because it uses a declaration idiom that was not hard-coded.

2. **SQL injection detector (AGT-006).** New `detect_sql_injection_static`
   flags `execute()`-family calls whose query is built by f-string, `+`
   concatenation, `%` formatting, or `.format()`. Parameterised queries are not
   flagged. Scans the whole source, since an agent's data layer is often a
   separate module.

**Result on DVLA:** findings rose from 2 (generic secrets only) to 5 — now
including the CRITICAL tool-chaining vector and both SQL-injection sites, the
vulnerabilities DVLA was purpose-built to demonstrate.

**No regression:** single-file benchmark unchanged at F1 = 0.889, project
benchmark unchanged at F1 = 0.857, both negative controls still clean, DVLA
deterministic across 5 runs.
