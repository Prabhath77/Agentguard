# =============================================================================
# validator.py — The Self-Validation Loop Orchestrator
# =============================================================================
# This is where the magic happens. For each finding from the analyzer:
#   1. Generate one or more diverse exploit attempts (Phase 3)
#   2. Run each in the sandbox (Phase 4)
#   3. Classify the result into one of three buckets:
#        CONFIRMED  — exploit succeeded
#        SUSPECTED  — finding looks real but PoC inconclusive
#        DISMISSED  — finding could not be reproduced
#   4. If all attempts failed and LLM is enabled, ask the LLM to write
#      a NEW exploit with a different angle, up to MAX_ADAPTIVE_RETRIES
#
# The output of this stage is a list of ValidatedFindings — each with a
# bucket assignment, confidence score, and the exploit evidence.
# =============================================================================

import json
from dataclasses import dataclass, field, asdict
from typing import List, Optional
from enum import Enum

from .analyzer          import Finding
from .parser            import AgentManifest
from .exploit_generator import (
    Exploit, generate_exploits_for_finding, _generate_exploit_via_llm,
    _find_target_tool
)
from .sandbox_runner    import run_exploit, SandboxResult


# ─── Validation buckets ──────────────────────────────────────────────────────

class Bucket(Enum):
    CONFIRMED = "CONFIRMED"     # Exploit fired and produced real impact
    SUSPECTED = "SUSPECTED"     # Finding plausible, exploit incomplete
    DISMISSED = "DISMISSED"     # Could not reproduce — likely false positive


# ─── Validated finding data class ────────────────────────────────────────────

@dataclass
class ValidatedFinding:
    """A finding that has been through the validation loop."""
    finding:          Finding
    bucket:           str
    final_confidence: float
    attempts:         List[dict] = field(default_factory=list)   # Each attempt's result
    notes:            List[str] = field(default_factory=list)
    ai_hypothesis:    str = ""    # AI-prover: why it believed the code vulnerable
    ai_method:        str = ""    # AI-prover: what its exploit did
    ai_exploit_code:  str = ""    # AI-prover: the actual code it wrote and ran
    ai_fix:           str = ""    # AI-prover: the specific fix that closes it
    ai_verdict:       str = ""    # AI-prover: CONFIRMED / SUSPECTED / COULD-NOT-TEST (by execution)
    ai_tokens_in:      int = 0    # actual tokens used by the AI-prover call for this finding
    ai_tokens_out:     int = 0
    ai_tokens_thinking: int = 0

    def to_dict(self):
        return {
            "finding":          self.finding.to_dict(),
            "bucket":           self.bucket,
            "final_confidence": self.final_confidence,
            "attempts":         self.attempts,
            "notes":            self.notes,
            "ai_hypothesis":    self.ai_hypothesis,
            "ai_method":        self.ai_method,
            "ai_exploit_code":  self.ai_exploit_code,
            "ai_fix":           self.ai_fix,
            "ai_verdict":       self.ai_verdict,
            "ai_tokens_in":       self.ai_tokens_in,
            "ai_tokens_out":      self.ai_tokens_out,
            "ai_tokens_thinking": self.ai_tokens_thinking,
        }


# ─── Bucket assignment thresholds ────────────────────────────────────────────

CONFIDENCE_THRESHOLDS = {
    "CONFIRMED": 0.70,    # Need at least one strong success
    "SUSPECTED": 0.20,    # Some signal but not enough
    # below 0.20 → DISMISSED
}


def _bucket_from_confidence(confidence: float, finding: Finding) -> str:
    """
    Assign a bucket based on best confidence and finding metadata.
    Static-source findings (deterministic detectors) get a floor — even
    if exploit fails, a static-detected secret IS a real finding.
    """
    # Special case: AGT-007 (secrets) found by deterministic regex never
    # gets dismissed — the secret IS in the source code, period.
    if finding.vuln_id == "AGT-007" and finding.confidence >= 0.95:
        if confidence >= CONFIDENCE_THRESHOLDS["CONFIRMED"]:
            return Bucket.CONFIRMED.value
        return Bucket.SUSPECTED.value   # never DISMISSED

    if confidence >= CONFIDENCE_THRESHOLDS["CONFIRMED"]:
        return Bucket.CONFIRMED.value
    if confidence >= CONFIDENCE_THRESHOLDS["SUSPECTED"]:
        return Bucket.SUSPECTED.value
    return Bucket.DISMISSED.value


# ─── Adaptive retry with LLM ─────────────────────────────────────────────────

MAX_ADAPTIVE_RETRIES = 2


def _build_adaptive_prompt(finding: Finding, manifest: AgentManifest,
                            previous_attempts: List[dict]) -> Exploit:
    """
    When all template-based attempts fail, ask the LLM to write a new
    exploit *informed by* the failure modes of previous attempts.
    """
    history_summary = "\n".join(
        f"  Attempt {i+1}: strategy={a.get('strategy','?')}, "
        f"success_level={a.get('success_level','?')}, "
        f"flags_seen={a.get('flags_seen', [])}, "
        f"key_stderr={a.get('stderr','')[:200].strip()}"
        for i, a in enumerate(previous_attempts)
    )

    # Reuse the LLM exploit generator, but with extra context appended
    tool = _find_target_tool(finding, manifest)
    base_exploit = _generate_exploit_via_llm(finding, manifest, tool)
    if not base_exploit:
        return None

    # Annotate with retry context
    base_exploit.strategy = (
        f"Adaptive retry (after {len(previous_attempts)} previous failures): "
        + base_exploit.strategy
    )
    base_exploit.code = (
        f"# Adaptive retry — informed by previous failures:\n"
        f"# {history_summary.replace(chr(10), chr(10) + '# ')}\n\n"
        + base_exploit.code
    )
    return base_exploit


# ─── Main validation function ────────────────────────────────────────────────

def validate_finding(finding: Finding, manifest: AgentManifest,
                      use_llm_fallback: bool = True,
                      run_benign: bool = True,
                      ai_prover_first: bool = False,
                      verbose: bool = True) -> ValidatedFinding:
    """
    Validate one finding by attempting to exploit it in the sandbox.
    Tries multiple strategies; returns a ValidatedFinding with bucket.

    When ai_prover_first is True, the AI-driven prover runs BEFORE the
    deterministic templates. This is used to demonstrate that the AI can
    independently author and execute a working exploit — otherwise a template
    that confirms first (and early-exits) would never give the AI its turn.
    In normal operation ai_prover_first is False: templates run first because
    they are fast and deterministic, and the AI-prover is the fallback for
    what they cannot confirm.
    """
    if verbose:
        print(f"\n  [Validating] {finding.vuln_id} @ {finding.location}")

    attempts: List[dict] = []
    best_confidence = 0.0
    best_level      = "NONE"
    notes: List[str] = []
    ai_hypothesis = ai_method = ai_exploit_code = ai_fix = ai_verdict = ""
    ai_tok_in = ai_tok_out = ai_tok_thinking = 0

    # ── AI-prover FIRST (demonstration mode) ─────────────────────────────────
    if ai_prover_first and use_llm_fallback:
        if verbose:
            print(f"    [AI-prover FIRST] Asking the AI to write and run its own exploit")
        from .exploit_generator import generate_ai_prover_exploit
        ai_exploit = generate_ai_prover_exploit(
            finding, manifest, _find_target_tool(finding, manifest))
        if ai_exploit is not None:
            ai_hypothesis   = ai_exploit.hypothesis
            ai_method       = ai_exploit.method
            ai_exploit_code = ai_exploit.code
            ai_fix          = ai_exploit.fix
            ai_tok_in       = getattr(ai_exploit, "tokens_in", 0)
            ai_tok_out      = getattr(ai_exploit, "tokens_out", 0)
            ai_tok_thinking = getattr(ai_exploit, "tokens_thinking", 0)
            result = run_exploit(ai_exploit, manifest.file_path, run_benign=False)
            attempts.append({
                "attempt": len(attempts) + 1, "strategy": ai_exploit.strategy,
                "source": "ai-prover", "success_level": result.success_level,
                "confidence": result.confidence, "elapsed_sec": result.elapsed_sec,
                "timed_out": result.timed_out, "crashed": result.crashed,
                "flags_seen": result.flags_seen, "stdout_excerpt": result.stdout[:500],
                "stderr": result.stderr[:500], "notes": result.notes,
            })
            if verbose:
                lvl = {"EXTRACTED": "✅", "TRIGGERED": "🟢",
                       "REACHED": "🟡", "NONE": "⚪"}.get(result.success_level, "?")
                print(f"      → {lvl} {result.success_level} "
                      f"(conf={result.confidence}) via AI-authored exploit")
            if result.confidence > best_confidence:
                best_confidence = result.confidence
                best_level      = result.success_level
            if result.success_level == "EXTRACTED":
                ai_verdict = "CONFIRMED (AI exploit executed and proved it)"
            elif result.success_level in ("TRIGGERED", "REACHED"):
                ai_verdict = "SUSPECTED (AI exploit ran but proof was inconclusive)"
            else:
                ai_verdict = "COULD-NOT-TEST (AI exploit did not fire)"

    # ── Phase 3: Generate template-based exploits ────────────────────────────
    exploits = generate_exploits_for_finding(
        finding, manifest, use_llm=False
    )

    # ── Phase 3b: Add stateful multi-turn exploits if applicable ─────────────
    from .stateful_exploit import generate_stateful_exploits
    stateful_exploits = generate_stateful_exploits(finding, manifest)
    if stateful_exploits:
        exploits.extend(stateful_exploits)
        if verbose:
            print(f"    [Stateful] Added {len(stateful_exploits)} multi-turn exploit(s)")

    if not exploits and use_llm_fallback:
        if verbose:
            print(f"    [No template] Falling back to LLM exploit generation")
        exploits = generate_exploits_for_finding(
            finding, manifest, use_llm=True
        )

    if not exploits:
        notes.append("No exploit could be generated for this finding "
                       "(no template, LLM fallback disabled or failed).")
        return ValidatedFinding(
            finding          = finding,
            bucket           = Bucket.SUSPECTED.value,    # don't dismiss; just no PoC
            final_confidence = finding.confidence * 0.5,   # halve confidence
            attempts         = [],
            notes            = notes,
        )

    # ── Phase 4: Run each exploit in the sandbox ─────────────────────────────
    for i, exploit in enumerate(exploits, 1):
        if verbose:
            print(f"    [Attempt {i}] {exploit.strategy[:80]}")

        result = run_exploit(exploit, manifest.file_path, run_benign=run_benign)

        attempt_record = {
            "attempt":          i,
            "strategy":         exploit.strategy,
            "source":           exploit.source,
            "success_level":    result.success_level,
            "confidence":       result.confidence,
            "elapsed_sec":      result.elapsed_sec,
            "timed_out":        result.timed_out,
            "crashed":          result.crashed,
            "flags_seen":       result.flags_seen,
            "benign_clean":     result.benign_clean,
            "stdout_excerpt":   result.stdout[:500],
            "stderr":           result.stderr[:500],
            "notes":            result.notes,
        }
        attempts.append(attempt_record)

        if verbose:
            level_emoji = {"EXTRACTED": "✅", "TRIGGERED": "🟢",
                            "REACHED": "🟡", "NONE": "⚪"}.get(result.success_level, "?")
            print(f"      → {level_emoji} {result.success_level} "
                  f"(conf={result.confidence}) in {result.elapsed_sec}s")

        if result.confidence > best_confidence:
            best_confidence = result.confidence
            best_level      = result.success_level

        # Early exit — if we got EXTRACTED with high confidence, no need to
        # keep trying other angles. The vuln is confirmed.
        if result.success_level == "EXTRACTED" and result.confidence >= 0.90:
            if verbose:
                print(f"      [Early exit] High-confidence proof obtained.")
            break

    # ── AI-driven self-validation prover ─────────────────────────────────────
    # If the deterministic templates did not CONFIRM the finding, hand the raw
    # code to the AI and let it act as the exploit author: state a hypothesis,
    # write a bespoke proof-of-concept for THIS code, and propose the fix. The
    # exploit it writes is still EXECUTED in the sandbox — a CONFIRMED verdict is
    # earned only by that execution succeeding, never by the AI's opinion. The
    # hypothesis, method, code and fix are captured for full transparency.
    # Skipped if the AI-prover already ran first (ai_prover_first mode).
    if (not ai_prover_first
            and best_confidence < CONFIDENCE_THRESHOLDS["CONFIRMED"]
            and use_llm_fallback):
        if verbose:
            print(f"    [AI-prover] Asking the AI to write and run its own exploit")
        from .exploit_generator import generate_ai_prover_exploit
        ai_exploit = generate_ai_prover_exploit(finding, manifest, _find_target_tool(finding, manifest))
        if ai_exploit is not None:
            ai_hypothesis   = ai_exploit.hypothesis
            ai_method       = ai_exploit.method
            ai_exploit_code = ai_exploit.code
            ai_fix          = ai_exploit.fix
            ai_tok_in       = getattr(ai_exploit, "tokens_in", 0)
            ai_tok_out      = getattr(ai_exploit, "tokens_out", 0)
            ai_tok_thinking = getattr(ai_exploit, "tokens_thinking", 0)

            result = run_exploit(ai_exploit, manifest.file_path, run_benign=False)
            attempts.append({
                "attempt":        len(attempts) + 1,
                "strategy":       ai_exploit.strategy,
                "source":         "ai-prover",
                "success_level":  result.success_level,
                "confidence":     result.confidence,
                "elapsed_sec":    result.elapsed_sec,
                "timed_out":      result.timed_out,
                "crashed":        result.crashed,
                "flags_seen":     result.flags_seen,
                "stdout_excerpt": result.stdout[:500],
                "stderr":         result.stderr[:500],
                "notes":          result.notes,
            })
            if verbose:
                lvl = {"EXTRACTED": "✅", "TRIGGERED": "🟢",
                       "REACHED": "🟡", "NONE": "⚪"}.get(result.success_level, "?")
                print(f"      → {lvl} {result.success_level} "
                      f"(conf={result.confidence}) via AI-authored exploit")
            if result.confidence > best_confidence:
                best_confidence = result.confidence
                best_level      = result.success_level
            # The AI's verdict is decided by EXECUTION, not its own claim.
            if result.success_level == "EXTRACTED":
                ai_verdict = "CONFIRMED (AI exploit executed and proved it)"
            elif result.success_level in ("TRIGGERED", "REACHED"):
                ai_verdict = "SUSPECTED (AI exploit ran but proof was inconclusive)"
            else:
                ai_verdict = "COULD-NOT-TEST (AI exploit did not fire)"

    # ── Bucket assignment ────────────────────────────────────────────────────
    bucket = _bucket_from_confidence(best_confidence, finding)

    # If exploit confirmed, prefer exploit confidence; otherwise keep static finding's
    final_confidence = max(best_confidence, finding.confidence
                            if bucket != Bucket.DISMISSED.value else 0.0)

    if verbose:
        bucket_emoji = {"CONFIRMED": "✅", "SUSPECTED": "🟡",
                         "DISMISSED": "❌"}[bucket]
        print(f"    [Bucket] {bucket_emoji} {bucket}  (final conf: {final_confidence:.2f})")

    return ValidatedFinding(
        finding          = finding,
        bucket           = bucket,
        final_confidence = round(final_confidence, 2),
        attempts         = attempts,
        notes            = notes,
        ai_hypothesis    = ai_hypothesis,
        ai_method        = ai_method,
        ai_exploit_code  = ai_exploit_code,
        ai_fix           = ai_fix,
        ai_verdict       = ai_verdict,
        ai_tokens_in       = ai_tok_in,
        ai_tokens_out      = ai_tok_out,
        ai_tokens_thinking = ai_tok_thinking,
    )


# ─── Batch validation ────────────────────────────────────────────────────────

def validate_findings(findings: List[Finding], manifest: AgentManifest,
                       use_llm_fallback: bool = True,
                       run_benign: bool = True,
                       ai_prover_first: bool = False,
                       verbose: bool = True) -> List[ValidatedFinding]:
    """Validate every finding. Returns one ValidatedFinding per input finding."""
    if verbose:
        print(f"\n{'═'*60}")
        print(f"  PHASE 3+4: SELF-VALIDATION LOOP")
        print(f"  Findings to validate: {len(findings)}")
        print(f"{'═'*60}")

    validated = []
    for f in findings:
        v = validate_finding(f, manifest,
                              use_llm_fallback = use_llm_fallback,
                              run_benign       = run_benign,
                              ai_prover_first  = ai_prover_first,
                              verbose          = verbose)
        validated.append(v)

    return validated


# ─── Summary printing ────────────────────────────────────────────────────────

def print_validation_summary(validated: List[ValidatedFinding]):
    confirmed = [v for v in validated if v.bucket == "CONFIRMED"]
    suspected = [v for v in validated if v.bucket == "SUSPECTED"]
    dismissed = [v for v in validated if v.bucket == "DISMISSED"]

    print(f"\n{'═'*60}")
    print(f"  VALIDATION SUMMARY")
    print(f"{'═'*60}")
    print(f"  ✅  CONFIRMED:  {len(confirmed)}")
    print(f"  🟡  SUSPECTED:  {len(suspected)}")
    print(f"  ❌  DISMISSED:  {len(dismissed)}")
    print()

    if confirmed:
        print(f"  CONFIRMED VULNERABILITIES (exploit succeeded):")
        for v in confirmed:
            print(f"    ✅ [{v.finding.vuln_id}] {v.finding.vuln_name}")
            print(f"       └─ {v.finding.location}")
            print(f"       └─ confidence: {v.final_confidence:.0%}")
        print()
    if suspected:
        print(f"  SUSPECTED (manual review needed):")
        for v in suspected:
            print(f"    🟡 [{v.finding.vuln_id}] {v.finding.vuln_name}")
            print(f"       └─ {v.finding.location}")
        print()
    if dismissed:
        print(f"  DISMISSED ({len(dismissed)} likely false positive(s))")
        print()
