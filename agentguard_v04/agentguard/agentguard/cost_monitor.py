# =============================================================================
# cost_monitor.py — Token Optimizer & Cost Tracking
# =============================================================================
# Tracks every LLM call: prompt tokens, completion tokens, estimated cost.
# Provides a context pruner that removes irrelevant code regions before
# sending to the LLM, reducing token usage without losing detection signal.
#
# Output: per-scan cost report + commercial-moat metric ("scan optimised
# from X tokens to Y tokens, Z% reduction").
# =============================================================================

import re
import json
import time
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional
from pathlib import Path


# Pricing as of 2026-05 (per million tokens, in USD)
PRICING = {
    "claude-sonnet-4-20250514":   {"input": 3.00,  "output": 15.00},
    "claude-opus-4-7":            {"input": 15.00, "output": 75.00},
    "claude-haiku-4-5-20251001":  {"input": 1.00,  "output": 5.00},
    # Fallback for unknown models
    "default":                    {"input": 3.00,  "output": 15.00},
}


@dataclass
class TokenUsage:
    """One LLM call's resource use."""
    timestamp:    float
    purpose:      str          # "tool_analysis", "exploit_gen", "remediation", etc.
    model:        str
    input_tokens:  int
    output_tokens: int
    cost_usd:      float
    pruned_input_tokens: int = 0   # Tokens saved by context pruning
    cache_hit:    bool = False

    def to_dict(self):
        return asdict(self)


@dataclass
class CostReport:
    """Aggregate cost data for an entire scan."""
    total_calls:        int = 0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_cost_usd:     float = 0.0
    pruned_tokens_saved: int = 0
    cache_hits:         int = 0
    per_purpose:        Dict[str, dict] = field(default_factory=dict)
    calls:              List[TokenUsage] = field(default_factory=list)

    def to_dict(self):
        return {
            "total_calls":         self.total_calls,
            "total_input_tokens":  self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "total_cost_usd":      round(self.total_cost_usd, 4),
            "pruned_tokens_saved": self.pruned_tokens_saved,
            "tokens_would_have_been": (
                self.total_input_tokens + self.pruned_tokens_saved
            ),
            "reduction_percent": round(
                100 * self.pruned_tokens_saved /
                (self.total_input_tokens + self.pruned_tokens_saved)
                if (self.total_input_tokens + self.pruned_tokens_saved) > 0 else 0,
                1
            ),
            "cache_hits":          self.cache_hits,
            "per_purpose":         self.per_purpose,
            "call_count":          len(self.calls),
        }


# Module-level singleton — gets reset per scan
_global_report = CostReport()
_response_cache: Dict[str, str] = {}     # Simple in-memory cache


def reset_cost_tracker():
    """Call at the start of each scan to zero the counters."""
    global _global_report, _response_cache
    _global_report = CostReport()
    _response_cache = {}


def get_cost_report() -> CostReport:
    return _global_report


def estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    """Compute USD cost from token counts."""
    p = PRICING.get(model, PRICING["default"])
    return (input_tokens / 1_000_000) * p["input"] + \
           (output_tokens / 1_000_000) * p["output"]


def record_call(purpose: str, model: str,
                input_tokens: int, output_tokens: int,
                pruned_input_tokens: int = 0,
                cache_hit: bool = False):
    """Record one LLM call into the global cost report."""
    cost = estimate_cost(model, input_tokens, output_tokens)
    usage = TokenUsage(
        timestamp           = time.time(),
        purpose             = purpose,
        model               = model,
        input_tokens        = input_tokens,
        output_tokens       = output_tokens,
        cost_usd            = round(cost, 5),
        pruned_input_tokens = pruned_input_tokens,
        cache_hit           = cache_hit,
    )

    _global_report.calls.append(usage)
    _global_report.total_calls         += 1
    _global_report.total_input_tokens  += input_tokens
    _global_report.total_output_tokens += output_tokens
    _global_report.total_cost_usd      += cost
    _global_report.pruned_tokens_saved += pruned_input_tokens
    if cache_hit:
        _global_report.cache_hits      += 1

    # Per-purpose breakdown
    if purpose not in _global_report.per_purpose:
        _global_report.per_purpose[purpose] = {
            "calls": 0, "input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0
        }
    p = _global_report.per_purpose[purpose]
    p["calls"] += 1
    p["input_tokens"] += input_tokens
    p["output_tokens"] += output_tokens
    p["cost_usd"] = round(p["cost_usd"] + cost, 5)


# ─── Caching ─────────────────────────────────────────────────────────────────

def cache_key(prompt: str, model: str) -> str:
    """Cheap hash of (prompt, model) for caching identical calls."""
    import hashlib
    h = hashlib.sha256()
    h.update(model.encode("utf-8"))
    h.update(b"|")
    h.update(prompt.encode("utf-8"))
    return h.hexdigest()


def cache_get(key: str) -> Optional[str]:
    return _response_cache.get(key)


def cache_set(key: str, response: str):
    if len(_response_cache) > 1000:
        # Simple cap — drop oldest
        _response_cache.pop(next(iter(_response_cache)))
    _response_cache[key] = response


# ─── Token counting (approximation) ──────────────────────────────────────────

def count_tokens(text: str) -> int:
    """
    Rough token estimate. Real tokenization is model-specific; for cost
    tracking purposes this approximation (~4 chars per token for English,
    ~3 for code) is accurate within ~10%.
    """
    if not text:
        return 0
    # Heuristic: code is ~3 chars/token, prose is ~4
    code_chars = sum(1 for c in text if c in "{}[]()<>=+-*/;:#")
    if code_chars / max(len(text), 1) > 0.05:
        return max(1, len(text) // 3)
    return max(1, len(text) // 4)


# ─── Context pruning ─────────────────────────────────────────────────────────

# Patterns that almost never contain vulnerability signal — safe to strip
PRUNABLE_PATTERNS = [
    (r"^\s*#.*$",                          "single-line comment"),
    (r'^\s*"""[^"]*"""\s*$',                "module docstring"),
    (r"^\s*import\s+\S+\s*$",               "import line"),
    (r"^\s*from\s+\S+\s+import\s+.*$",      "from-import"),
    (r"^\s*$",                              "blank line"),
    (r"^\s*pass\s*$",                       "pass statement"),
    (r"^\s*\.\.\.\s*$",                     "ellipsis"),
]


def prune_code_for_llm(code: str, preserve_lines: Optional[List[int]] = None,
                        preserve_comments: bool = True) -> tuple[str, int]:
    """
    Strip lines that are extremely unlikely to contain vulnerability signal.
    Returns (pruned_code, original_token_count - pruned_token_count).

    preserve_lines:     1-indexed line numbers we MUST keep regardless of pattern
    preserve_comments:  If True (default), comments are KEPT — they often
                        reveal critical context (secrets, security notes,
                        TODOs the developer forgot about). Only set False
                        if you have a specific token-budget reason.
    """
    original_tokens = count_tokens(code)
    preserve = set(preserve_lines or [])

    pruned_lines = []
    for idx, line in enumerate(code.splitlines(), 1):
        if idx in preserve:
            pruned_lines.append(line)
            continue
        # Check prunable patterns — but skip comment patterns if we're preserving them
        prune_set = PRUNABLE_PATTERNS
        if preserve_comments:
            prune_set = [(pat, name) for pat, name in PRUNABLE_PATTERNS
                          if "comment" not in name]
        is_prunable = any(re.match(pat, line) for pat, _ in prune_set)
        if not is_prunable:
            pruned_lines.append(line)

    pruned = "\n".join(pruned_lines)
    pruned_tokens = count_tokens(pruned)
    tokens_saved = max(0, original_tokens - pruned_tokens)
    return pruned, tokens_saved


def smart_truncate(text: str, max_tokens: int) -> tuple[str, int]:
    """
    Truncate text to roughly max_tokens, preserving start AND end
    (where signatures and return statements often live).
    """
    current = count_tokens(text)
    if current <= max_tokens:
        return text, 0

    # Keep 60% from the top, 40% from the bottom
    char_budget = max_tokens * 3   # rough conversion
    top_chars   = int(char_budget * 0.6)
    bot_chars   = int(char_budget * 0.4)
    truncated = (
        text[:top_chars]
        + f"\n\n# ... [SMART TRUNCATED — {current - max_tokens} tokens removed] ...\n\n"
        + text[-bot_chars:]
    )
    saved = current - count_tokens(truncated)
    return truncated, max(0, saved)


# ─── Pretty printing ─────────────────────────────────────────────────────────

def print_cost_summary():
    r = _global_report
    print(f"\n{'═'*60}")
    print(f"  COST & TOKEN REPORT")
    print(f"{'═'*60}")
    print(f"  Total LLM calls:        {r.total_calls}")
    print(f"  Input tokens:           {r.total_input_tokens:,}")
    print(f"  Output tokens:          {r.total_output_tokens:,}")
    print(f"  Estimated cost:         ${r.total_cost_usd:.4f}")
    print(f"  Cache hits:             {r.cache_hits}")
    if r.pruned_tokens_saved > 0:
        saved_pct = 100 * r.pruned_tokens_saved / (
            r.total_input_tokens + r.pruned_tokens_saved
        )
        print(f"  Tokens saved by pruning: {r.pruned_tokens_saved:,} ({saved_pct:.1f}%)")
    if r.per_purpose:
        print(f"\n  Breakdown by purpose:")
        for purpose, stats in sorted(r.per_purpose.items(),
                                       key=lambda x: -x[1]["cost_usd"]):
            print(f"    {purpose:<25} {stats['calls']:>3} calls  "
                  f"${stats['cost_usd']:.4f}")
    print()
