# =============================================================================
# reasoning_log.py — Explainability Layer
# =============================================================================
# Every meaningful decision the system makes — what was detected, why an
# exploit was chosen, how it was refined, why a fix was suggested — is
# captured as a structured ReasoningStep.
#
# The final report includes a "Reasoning Log" section that shows the chain
# of decisions. This is critical for:
#   - Academic credibility (explainability is a research expectation)
#   - Customer trust (CISOs want to see WHY a finding is reported)
#   - Debugging (when something goes wrong, the log shows where)
# =============================================================================

import time
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any
from enum import Enum


class StepType(Enum):
    DETECTION         = "DETECTION"          # Found a candidate finding
    HYPOTHESIS        = "HYPOTHESIS"          # Formed a theory about the vuln
    EXPLOIT_PLAN      = "EXPLOIT_PLAN"        # Decided on attack strategy
    EXPLOIT_ATTEMPT   = "EXPLOIT_ATTEMPT"     # Ran a PoC
    REFLECTION        = "REFLECTION"          # Analysed why an attempt failed
    PIVOT             = "PIVOT"               # Switched strategy
    CONFIRMATION      = "CONFIRMATION"        # Established the vuln is real
    DISMISSAL         = "DISMISSAL"           # Decided the finding is false
    REMEDIATION       = "REMEDIATION"         # Proposed a fix
    VERIFICATION      = "VERIFICATION"        # Re-scanned after applying fix


@dataclass
class ReasoningStep:
    timestamp: float
    step_type: str
    summary:   str             # 1-line headline of what happened
    detail:    str             # Multi-line explanation
    finding_id: Optional[str] = None     # Which finding this step relates to
    attempt_num: Optional[int] = None    # Which exploit attempt (if applicable)
    evidence:  Optional[str] = None      # Code/output/excerpt supporting this step
    confidence: Optional[float] = None
    metadata:  Dict[str, Any] = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)


@dataclass
class ReasoningLog:
    """Sequential log for one full scan."""
    steps: List[ReasoningStep] = field(default_factory=list)

    def add(self, step_type: StepType, summary: str, detail: str = "",
            finding_id: Optional[str] = None,
            attempt_num: Optional[int] = None,
            evidence: Optional[str] = None,
            confidence: Optional[float] = None,
            **metadata):
        step = ReasoningStep(
            timestamp   = time.time(),
            step_type   = step_type.value,
            summary     = summary,
            detail      = detail,
            finding_id  = finding_id,
            attempt_num = attempt_num,
            evidence    = evidence[:500] if evidence else None,  # cap evidence size
            confidence  = confidence,
            metadata    = metadata,
        )
        self.steps.append(step)
        return step

    def for_finding(self, finding_id: str) -> List[ReasoningStep]:
        """Get all reasoning steps related to one finding."""
        return [s for s in self.steps if s.finding_id == finding_id]

    def render_chain(self, finding_id: Optional[str] = None) -> str:
        """Human-readable summary of the reasoning chain."""
        steps = self.for_finding(finding_id) if finding_id else self.steps
        if not steps:
            return "(no reasoning steps recorded)"

        lines = []
        for i, s in enumerate(steps, 1):
            attempt_str = f" [attempt {s.attempt_num}]" if s.attempt_num else ""
            lines.append(f"  {i}. [{s.step_type}]{attempt_str} {s.summary}")
            if s.detail:
                for dl in s.detail.split("\n"):
                    if dl.strip():
                        lines.append(f"       {dl.strip()}")
        return "\n".join(lines)

    def to_dict(self):
        return {"steps": [s.to_dict() for s in self.steps]}


# ─── Module-level singleton ──────────────────────────────────────────────────

_global_log = ReasoningLog()


def reset_reasoning_log():
    """Call at the start of each scan."""
    global _global_log
    _global_log = ReasoningLog()


def get_reasoning_log() -> ReasoningLog:
    return _global_log


def log_step(step_type: StepType, summary: str, **kwargs) -> ReasoningStep:
    """Module-level convenience to add to the singleton log."""
    return _global_log.add(step_type, summary, **kwargs)
