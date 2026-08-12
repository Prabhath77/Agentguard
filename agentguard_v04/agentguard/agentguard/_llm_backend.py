# =============================================================================
# _llm_backend.py — Provider-Agnostic LLM Adapter
# =============================================================================
# A single chat() function that works across four providers:
#
#   - gemini     Google AI Studio      FREE, no card, 1M-token context  (DEFAULT)
#   - groq       Groq Cloud            FREE, no card, fastest inference
#   - openai     any OpenAI-compatible endpoint
#   - anthropic  native Claude API     (paid)
#
# Every LLM call site in AgentGuard funnels through chat(), so switching
# providers is one environment variable. Implemented with the `requests`
# library only — no provider SDKs required — which keeps installation on a
# fresh VM to a single dependency and avoids SDK version drift.
# =============================================================================

import os
import sys
import time
import threading
from dataclasses import dataclass
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import (
    LLM_PROVIDER, LLM_API_KEY, LLM_BASE_URL, LLM_MODEL, MAX_TOKENS,
)

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None


# ─── Result container ────────────────────────────────────────────────────────

@dataclass
class BackendResult:
    text:            str
    input_tokens:    int
    output_tokens:   int
    thinking_tokens: int = 0   # invisible reasoning tokens, Gemini "thinking" models
    provider:        str = ""
    model:           str = ""


class LLMBackendError(RuntimeError):
    """Raised when the provider call fails after retries."""


# ─── Usage tracking (for cost/timing evaluation) ─────────────────────────────
# A simple cumulative counter every chat() call updates. Reset with
# reset_usage() at the start of a measured run, read with get_usage() after.
# Free tiers (Gemini/Groq) cost $0 in reality; the "estimated_cost" fields use
# a documented paid-tier reference rate purely so a dissertation can report a
# comparable dollar figure — see README "Cost accounting" for the rate used.

_usage_lock = threading.Lock()
_usage = {"requests": 0, "input_tokens": 0, "output_tokens": 0, "thinking_tokens": 0}

# Reference rate for the hypothetical-cost figure only (per 1K tokens, USD).
# Chosen to match a commonly cited small-model paid tier; NOT what you are
# actually being charged on a free Gemini/Groq key.
REFERENCE_RATE_INPUT_PER_1K  = 0.00015
REFERENCE_RATE_OUTPUT_PER_1K = 0.0006


def reset_usage():
    with _usage_lock:
        _usage["requests"] = 0
        _usage["input_tokens"] = 0
        _usage["output_tokens"] = 0
        _usage["thinking_tokens"] = 0


def get_usage() -> dict:
    with _usage_lock:
        u = dict(_usage)
    est_cost = (u["input_tokens"] / 1000 * REFERENCE_RATE_INPUT_PER_1K
                + u["output_tokens"] / 1000 * REFERENCE_RATE_OUTPUT_PER_1K)
    u["estimated_cost_usd_reference_rate"] = round(est_cost, 6)
    u["actual_cost_usd"] = 0.0 if LLM_PROVIDER in ("gemini", "groq") else None
    return u


def _record_usage(result: "BackendResult"):
    with _usage_lock:
        _usage["requests"] += 1
        _usage["input_tokens"] += result.input_tokens
        _usage["output_tokens"] += result.output_tokens
        _usage["thinking_tokens"] += getattr(result, "thinking_tokens", 0)


# ─── Config validation ───────────────────────────────────────────────────────

_PLACEHOLDER_KEYS = {
    "", "YOUR_API_KEY_HERE", "YOUR_GROQ_KEY_HERE",
    "YOUR_GEMINI_KEY_HERE", "YOUR_OPENAI_KEY_HERE", "None",
}


def key_is_configured() -> bool:
    """True when a real-looking API key is present for the active provider."""
    return bool(LLM_API_KEY) and LLM_API_KEY not in _PLACEHOLDER_KEYS


def provider_banner() -> str:
    """One-line human-readable description of the active backend."""
    status = "configured" if key_is_configured() else "NO KEY SET"
    return f"{LLM_PROVIDER} / {LLM_MODEL} ({status})"


# ─── Provider implementations ────────────────────────────────────────────────

def _chat_gemini(prompt: str, model: str, max_tokens: int,
                 system: Optional[str]) -> BackendResult:
    """
    Google AI Studio — Gemini generateContent endpoint.
    Free tier: no credit card, generous daily quota, 1M-token context window.
    """
    url = f"{LLM_BASE_URL}/models/{model}:generateContent"

    gen_config = {
        "maxOutputTokens": max_tokens,
        "temperature": 0.0,          # determinism matters for the benchmark
    }
    # Optionally cap "thinking" so tokens go to the visible answer rather than
    # invisible reasoning. This is OFF by default because the accepted value
    # varies by model: some accept thinkingBudget:0, others reject it with
    # "Thinking budget does not map to any valid thinking level" and return an
    # empty candidate. Only sent when the environment explicitly opts in, and
    # the request automatically retries WITHOUT it if the model rejects it.
    _want_no_thinking = os.environ.get("AGENTGUARD_DISABLE_THINKING", "").lower() in ("1", "true", "yes")
    if _want_no_thinking:
        gen_config["thinkingConfig"] = {"thinkingBudget": 0}

    body = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": gen_config,
        # These loosen Google's own post-generation content filter, which is a
        # DIFFERENT mechanism from the model's own trained refusal behaviour.
        # Included because it is legitimate, official, and free to try, but it
        # will only matter if a response is ever blocked with finishReason
        # SAFETY (empty candidate) rather than STOP (a normal, complete
        # response the model chose, by its own judgement, to fill with a
        # refusal). See the finishReason check below, which reports honestly
        # which of the two actually happened rather than assuming either.
        "safetySettings": [
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HARASSMENT",        "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_HATE_SPEECH",       "threshold": "BLOCK_NONE"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
        ],
    }
    if system:
        body["systemInstruction"] = {"parts": [{"text": system}]}

    def _post(payload):
        return requests.post(
            url,
            headers={
                "Content-Type": "application/json",
                "x-goog-api-key": LLM_API_KEY,
            },
            json=payload,
            timeout=120,
        )

    resp = _post(body)
    # If the model rejects thinkingConfig, or returns an empty candidate because
    # of it, retry once with a clean config (no thinkingConfig at all).
    if resp.status_code == 400 and "thinking" in resp.text.lower():
        body["generationConfig"].pop("thinkingConfig", None)
        resp = _post(body)
    resp.raise_for_status()
    data = resp.json()

    # Gemini can return a candidate with no parts (e.g. a safety stop). Report
    # honestly which happened rather than treating every empty/refusal case
    # the same way: finishReason SAFETY means Google's content filter blocked
    # the output; finishReason STOP with refusal text means the model itself,
    # by its own trained judgement, chose not to comply. safetySettings above
    # can only affect the former.
    text = ""
    candidates = data.get("candidates") or []
    if candidates:
        finish_reason = candidates[0].get("finishReason", "")
        if finish_reason == "SAFETY":
            print(f"  [Gemini] Blocked by content filter (finishReason=SAFETY) — "
                  f"safetySettings did not prevent this block.")
        parts = (candidates[0].get("content") or {}).get("parts") or []
        text = "".join(p.get("text", "") for p in parts)
    else:
        prompt_feedback = data.get("promptFeedback") or {}
        if prompt_feedback.get("blockReason"):
            print(f"  [Gemini] Prompt itself blocked before generation "
                  f"(blockReason={prompt_feedback['blockReason']}).")

    usage = data.get("usageMetadata") or {}
    return BackendResult(
        text            = text,
        input_tokens    = usage.get("promptTokenCount", 0),
        output_tokens   = usage.get("candidatesTokenCount", 0),
        thinking_tokens = usage.get("thoughtsTokenCount", 0),
        provider        = "gemini",
        model           = model,
    )


def _chat_openai_compatible(prompt: str, model: str, max_tokens: int,
                            system: Optional[str], provider: str) -> BackendResult:
    """
    Groq and OpenAI both speak the OpenAI chat-completions protocol.
    Groq's base URL is https://api.groq.com/openai/v1
    """
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})

    resp = requests.post(
        f"{LLM_BASE_URL}/chat/completions",
        headers={
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {LLM_API_KEY}",
        },
        json={
            "model":       model,
            "messages":    messages,
            "max_tokens":  max_tokens,
            "temperature": 0.0,
        },
        timeout=120,
    )
    resp.raise_for_status()
    data = resp.json()

    text = ""
    choices = data.get("choices") or []
    if choices:
        text = (choices[0].get("message") or {}).get("content") or ""

    usage = data.get("usage") or {}
    return BackendResult(
        text          = text,
        input_tokens  = usage.get("prompt_tokens", 0),
        output_tokens = usage.get("completion_tokens", 0),
        provider      = provider,
        model         = model,
    )


def _chat_anthropic(prompt: str, model: str, max_tokens: int,
                    system: Optional[str]) -> BackendResult:
    """Native Anthropic messages endpoint (paid)."""
    body = {
        "model":      model,
        "max_tokens": max_tokens,
        "messages":   [{"role": "user", "content": prompt}],
    }
    if system:
        body["system"] = system

    resp = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "Content-Type":      "application/json",
            "x-api-key":         LLM_API_KEY,
            "anthropic-version": "2023-06-01",
        },
        json=body,
        timeout=120,
    )
    resp.raise_for_status()
    data = resp.json()

    text = "".join(
        block.get("text", "")
        for block in (data.get("content") or [])
        if block.get("type") == "text"
    )
    usage = data.get("usage") or {}
    return BackendResult(
        text          = text,
        input_tokens  = usage.get("input_tokens", 0),
        output_tokens = usage.get("output_tokens", 0),
        provider      = "anthropic",
        model         = model,
    )


# ─── The single entry point ──────────────────────────────────────────────────

_RETRYABLE_STATUS = {429, 500, 502, 503, 504}


def chat(prompt: str,
         model: str = None,
         max_tokens: int = MAX_TOKENS,
         system: str = None,
         retries: int = 3) -> BackendResult:
    """
    Send a single-turn prompt to the active LLM provider.

    Retries on rate-limit and transient server errors with exponential backoff,
    which matters on free tiers where 429s are routine rather than exceptional.
    """
    if requests is None:
        raise LLMBackendError(
            "The 'requests' package is required. "
            "Install it with: pip3 install requests --break-system-packages"
        )
    if not key_is_configured():
        raise LLMBackendError(
            f"No API key set for provider '{LLM_PROVIDER}'. "
            f"Export the key first (see README) or run with --no-llm."
        )

    model = model or LLM_MODEL
    last_error = None

    for attempt in range(retries):
        try:
            if LLM_PROVIDER == "gemini":
                result = _chat_gemini(prompt, model, max_tokens, system)
            elif LLM_PROVIDER == "anthropic":
                result = _chat_anthropic(prompt, model, max_tokens, system)
            else:  # groq, openai, or any OpenAI-compatible endpoint
                result = _chat_openai_compatible(
                    prompt, model, max_tokens, system, LLM_PROVIDER
                )
            _record_usage(result)
            return result

        except Exception as exc:  # noqa: BLE001 — re-raised below
            last_error = exc
            status = getattr(getattr(exc, "response", None), "status_code", None)

            # Only back off and retry when it is worth retrying.
            if status in _RETRYABLE_STATUS and attempt < retries - 1:
                backoff = 2 ** attempt
                print(f"      [LLM] {status} from {LLM_PROVIDER}; "
                      f"retrying in {backoff}s "
                      f"(attempt {attempt + 2}/{retries})")
                time.sleep(backoff)
                continue
            break

    hint = ""
    status = getattr(getattr(last_error, "response", None), "status_code", None)
    if status == 404 and LLM_PROVIDER == "gemini":
        hint = (
            f" — model '{model}' was not found. Google renames Gemini model "
            f"IDs periodically. List the models your key can currently see with: "
            f"curl -s -H \"x-goog-api-key: $GEMINI_API_KEY\" "
            f"https://generativelanguage.googleapis.com/v1beta/models | grep '\"name\"' "
            f"— then export GEMINI_MODEL=\"<a name from that list, without 'models/'>\""
        )
    raise LLMBackendError(
        f"{LLM_PROVIDER} call failed after {retries} attempt(s): {last_error}{hint}"
    )


# ─── Self-test ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"Active backend: {provider_banner()}")
    if not key_is_configured():
        print("Set your API key first — see README.md, LLM Provider Setup.")
        sys.exit(1)
    result = chat("Reply with exactly the word: OK")
    print(f"Response:  {result.text.strip()!r}")
    print(f"Tokens:    in={result.input_tokens} out={result.output_tokens}")
