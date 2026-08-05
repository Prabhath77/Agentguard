# Manual Security Audit Protocol

This is the one item in the evaluation plan that cannot be automated: your
proposal commits to comparing AgentGuard against a **manual security audit**,
and a manual audit requires an actual human reading code without AI
assistance. Follow this protocol so the comparison is fair and the numbers
are defensible in a viva.

---

## Who should do it

Ideally **not you** — or if it must be you, do it *before* you have looked at
AgentGuard's own output for the same files, and disclose that in the write-up.
The point of the comparison is what a competent reviewer finds unaided; if the
reviewer has already seen AgentGuard's findings, the result is contaminated
and an examiner will discount it. A course-mate, your supervisor, or anyone
with general security literacy is a better choice than a second run by you.

## What to give the auditor

The same benchmark files AgentGuard was measured against, with the ground
truth withheld:

```
benchmark/vuln_01_overprivileged.py
benchmark/vuln_02_prompt_injection.py
benchmark/vuln_03_system_leak.py
benchmark/vuln_04_tool_chain.py
benchmark/vuln_05_secrets.py
benchmark/vuln_06_code_exec.py
benchmark/vuln_07_no_validation.py
benchmark/vuln_08_memory_poison.py
benchmark/vuln_09_comment_secret.py
benchmark/vuln_10_devious_comments.py
benchmark/safe_agent.py
```

Optionally also the five projects in `benchmark_projects/` if you have time
for a second, harder round (multi-file review is a meaningfully different
task from single-file review and is worth reporting separately).

## Time-box it

Security audits are not infinite — give the auditor a fixed budget and record
it. A reasonable budget for the 11 single-file agents is **60–90 minutes
total**, reviewed in one sitting. Write down the actual time taken; this
becomes your runtime comparison figure alongside AgentGuard's, Bandit's, and
Semgrep's.

## What to ask the auditor to produce

For each file, ask for:

1. A list of security issues found, each with a one-line description
2. Roughly which category it falls into, in their own words (don't show them
   the Agent Top 10 taxonomy beforehand — that would bias them toward your
   framework and defeat the point of an independent audit)
3. A rough severity if they're willing to guess (Critical/High/Medium/Low)

A simple table works:

| File | Issue found (auditor's own words) | Severity guess |
|---|---|---|
| vuln_01_overprivileged.py | | |
| vuln_02_prompt_injection.py | | |
| ... | | |

## Scoring it against AgentGuard afterwards

Once you have the auditor's raw list, **you** do the mapping — match each of
their findings to the closest Agent Top 10 class, the same way
`scripts/compare_tools.py` maps Bandit/Semgrep rule IDs to AGT classes. Then
compute the same three numbers:

- **Precision** — of the issues the auditor reported, how many correspond to
  a genuine expected vulnerability in `ground_truth.json`?
- **Recall** — of the vulnerabilities in `ground_truth.json`, how many did the
  auditor's list cover?
- **F1** — the harmonic mean of the two.

Be honest about judgment calls in this mapping, the same way the tool
comparison script documents its Bandit/Semgrep mapping in its header comment.
If the auditor described something in a way that could map to two different
AGT classes, say so in the write-up rather than silently picking whichever
makes the comparison look better.

## What to expect, and why it's still worth doing

A careful human auditor will likely catch some things static tools miss
(especially prompt-injection-flavoured issues that need reading intent, not
just pattern-matching) and will likely miss some things that require checking
multiple files against each other (the cross-file capability chains — humans
are worse than tools at holding five files in working memory at once). Both
outcomes are worth reporting plainly: the comparison is not about "AgentGuard
wins," it's about characterising where each approach's strengths and blind
spots actually are. A dissertation that reports "the human missed the
cross-file chain in project 01, exactly as a single-file-at-a-time reviewer
would" is making a *stronger* argument for your tool's value than one that
just claims a higher F1 number.

## Recording the result

Once you have the auditor's precision/recall/F1 and time taken, add a row to
the same comparison table `scripts/compare_tools.py` produces for
AgentGuard/Bandit/Semgrep. There's no automated way to feed a human's output
back into that script — do this one by hand in your write-up.
