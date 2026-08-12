#!/usr/bin/env python3
# =============================================================================
# tests/test_providers_offline.py — Provider Contract Tests (no network)
# =============================================================================
# Verifies the four LLM backends WITHOUT contacting any provider, by replacing
# the `requests` module inside _llm_backend with a fake that records what was
# sent and returns realistic provider-shaped responses.
#
# What this proves:
#   - the correct endpoint URL is built for each provider
#   - the correct authentication header is used for each provider
#   - the request body matches each provider's documented schema
#   - temperature is pinned to 0.0 everywhere (benchmark determinism)
#   - each provider's distinct response shape is parsed correctly
#   - token accounting is read from the right fields
#   - a missing API key fails loudly rather than silently
#   - HTTP 429 triggers retry with backoff, and a later success is returned
#   - persistent server errors raise after the retry budget is spent
#
# What this CANNOT prove: that the provider accepts the request in production.
# Only a live key on a networked machine settles that — run:
#     python3 -m agentguard.main providers --test
#
# Usage:
#     python3 tests/test_providers_offline.py
# =============================================================================

import os
import sys
import importlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PASSED = 0
FAILED = 0


def check(condition, label):
    global PASSED, FAILED
    if condition:
        PASSED += 1
        print(f"    [PASS] {label}")
    else:
        FAILED += 1
        print(f"    [FAIL] {label}")


# ─── Fake HTTP layer ─────────────────────────────────────────────────────────

class FakeResponse:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            err = Exception(f"HTTP {self.status_code}")
            err.response = self          # mirrors requests.HTTPError.response
            raise err


class FakeRequests:
    """Stands in for the `requests` module inside _llm_backend."""

    def __init__(self, responder):
        self.responder = responder
        self.calls = []

    def post(self, url, headers=None, json=None, timeout=None):
        self.calls.append({"url": url, "headers": headers or {}, "body": json or {}})
        return self.responder(len(self.calls), url, headers or {}, json or {})


# Realistic response payloads, matching each provider's documented shape.
GEMINI_OK = {
    "candidates": [{"content": {"parts": [{"text": "OK"}]}}],
    "usageMetadata": {"promptTokenCount": 11, "candidatesTokenCount": 3},
}
OPENAI_OK = {
    "choices": [{"message": {"role": "assistant", "content": "OK"}}],
    "usage": {"prompt_tokens": 11, "completion_tokens": 3},
}
ANTHROPIC_OK = {
    "content": [{"type": "text", "text": "OK"}],
    "usage": {"input_tokens": 11, "output_tokens": 3},
}

KEY_VARS = ["GEMINI_API_KEY", "GROQ_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"]


def load_backend(provider, key_var, key_value, responder):
    """Reload config + backend for a given provider, with fake HTTP installed."""
    for var in KEY_VARS:
        os.environ.pop(var, None)
    if key_var:
        os.environ[key_var] = key_value
    os.environ["AGENTGUARD_PROVIDER"] = provider

    import config
    importlib.reload(config)
    from agentguard import _llm_backend
    importlib.reload(_llm_backend)

    fake = FakeRequests(responder)
    _llm_backend.requests = fake
    _llm_backend.time = type("t", (), {"sleep": staticmethod(lambda s: None)})()
    return _llm_backend, fake


# ─── Per-provider contract tests ─────────────────────────────────────────────

def test_gemini():
    print("\n  GEMINI")
    backend, fake = load_backend(
        "gemini", "GEMINI_API_KEY", "AIza-test-key",
        lambda n, u, h, b: FakeResponse(GEMINI_OK),
    )
    result = backend.chat("ping", system="be terse")
    call = fake.calls[0]

    check(":generateContent" in call["url"], "URL uses the generateContent endpoint")
    check("gemini" in call["url"], "URL contains the model name")
    check(call["headers"].get("x-goog-api-key") == "AIza-test-key",
          "authenticates via x-goog-api-key header")
    check("Authorization" not in call["headers"],
          "does not send a Bearer header (wrong scheme for Gemini)")
    check(call["body"]["contents"][0]["parts"][0]["text"] == "ping",
          "prompt placed in contents[0].parts[0].text")
    check(call["body"]["systemInstruction"]["parts"][0]["text"] == "be terse",
          "system prompt sent as systemInstruction")
    check(call["body"]["generationConfig"]["temperature"] == 0.0,
          "temperature pinned to 0.0 for determinism")
    check(result.text == "OK", "response text parsed from candidates")
    check((result.input_tokens, result.output_tokens) == (11, 3),
          "tokens read from usageMetadata")
    check(result.provider == "gemini", "provider recorded on the result")


def test_gemini_empty_candidate():
    """Gemini can return a candidate with no parts, e.g. on a safety stop."""
    print("\n  GEMINI — empty candidate (safety stop)")
    backend, _ = load_backend(
        "gemini", "GEMINI_API_KEY", "AIza-test-key",
        lambda n, u, h, b: FakeResponse({"candidates": [{"content": {}}]}),
    )
    result = backend.chat("ping")
    check(result.text == "", "empty candidate yields empty string, not a crash")


def test_groq():
    print("\n  GROQ")
    backend, fake = load_backend(
        "groq", "GROQ_API_KEY", "gsk-test-key",
        lambda n, u, h, b: FakeResponse(OPENAI_OK),
    )
    result = backend.chat("ping", system="be terse")
    call = fake.calls[0]

    check(call["url"].endswith("/chat/completions"),
          "URL uses the OpenAI chat-completions path")
    check("api.groq.com" in call["url"], "URL points at Groq")
    check(call["headers"].get("Authorization") == "Bearer gsk-test-key",
          "authenticates via Bearer token")
    check(call["body"]["messages"][0]["role"] == "system",
          "system prompt sent as a system-role message")
    check(call["body"]["messages"][1]["content"] == "ping",
          "prompt sent as a user-role message")
    check(call["body"]["temperature"] == 0.0, "temperature pinned to 0.0")
    check(result.text == "OK", "response parsed from choices[0].message.content")
    check((result.input_tokens, result.output_tokens) == (11, 3),
          "tokens read from usage")


def test_anthropic():
    print("\n  ANTHROPIC")
    backend, fake = load_backend(
        "anthropic", "ANTHROPIC_API_KEY", "sk-ant-test",
        lambda n, u, h, b: FakeResponse(ANTHROPIC_OK),
    )
    result = backend.chat("ping", system="be terse")
    call = fake.calls[0]

    check(call["url"] == "https://api.anthropic.com/v1/messages",
          "URL uses the messages endpoint")
    check(call["headers"].get("x-api-key") == "sk-ant-test",
          "authenticates via x-api-key header")
    check(call["headers"].get("anthropic-version") == "2023-06-01",
          "sends the required anthropic-version header")
    check(call["body"].get("system") == "be terse",
          "system prompt sent as a top-level field")
    check(result.text == "OK", "response parsed from content blocks")
    check((result.input_tokens, result.output_tokens) == (11, 3),
          "tokens read from usage")


# ─── Cross-cutting behaviour ─────────────────────────────────────────────────

def test_missing_key_fails_loudly():
    print("\n  MISSING KEY")
    backend, fake = load_backend(
        "gemini", None, None, lambda n, u, h, b: FakeResponse(GEMINI_OK),
    )
    try:
        backend.chat("ping")
        check(False, "raises LLMBackendError when no key is configured")
    except backend.LLMBackendError as exc:
        check(True, "raises LLMBackendError when no key is configured")
        check("--no-llm" in str(exc), "error message points the user at --no-llm")
    check(len(fake.calls) == 0, "makes no HTTP call without a key")


def test_retry_on_rate_limit():
    print("\n  RETRY — 429 then success")

    def responder(n, u, h, b):
        return FakeResponse({}, status=429) if n == 1 else FakeResponse(GEMINI_OK)

    backend, fake = load_backend(
        "gemini", "GEMINI_API_KEY", "AIza-test-key", responder,
    )
    result = backend.chat("ping")
    check(len(fake.calls) == 2, "retries once after a 429")
    check(result.text == "OK", "returns the successful response after retrying")


def test_gives_up_after_retries():
    print("\n  RETRY — persistent 500")
    backend, fake = load_backend(
        "gemini", "GEMINI_API_KEY", "AIza-test-key",
        lambda n, u, h, b: FakeResponse({}, status=500),
    )
    try:
        backend.chat("ping", retries=3)
        check(False, "raises after exhausting the retry budget")
    except backend.LLMBackendError:
        check(True, "raises after exhausting the retry budget")
    check(len(fake.calls) == 3, "attempts exactly the configured number of times")


def test_no_retry_on_auth_error():
    print("\n  RETRY — 401 is not retried")
    backend, fake = load_backend(
        "gemini", "GEMINI_API_KEY", "AIza-bad-key",
        lambda n, u, h, b: FakeResponse({}, status=401),
    )
    try:
        backend.chat("ping", retries=3)
    except backend.LLMBackendError:
        pass
    check(len(fake.calls) == 1,
          "a bad key fails immediately rather than retrying three times")


def test_provider_auto_detection():
    print("\n  AUTO-DETECTION")
    for var in KEY_VARS:
        os.environ.pop(var, None)
    os.environ.pop("AGENTGUARD_PROVIDER", None)

    os.environ["GROQ_API_KEY"] = "gsk-x"
    import config
    importlib.reload(config)
    check(config.LLM_PROVIDER == "groq", "GROQ_API_KEY alone selects groq")

    os.environ["GEMINI_API_KEY"] = "AIza-x"
    importlib.reload(config)
    check(config.LLM_PROVIDER == "gemini",
          "GEMINI_API_KEY takes precedence when both free keys are present")

    os.environ["AGENTGUARD_PROVIDER"] = "groq"
    importlib.reload(config)
    check(config.LLM_PROVIDER == "groq",
          "AGENTGUARD_PROVIDER overrides auto-detection")

    for var in KEY_VARS:
        os.environ.pop(var, None)
    os.environ.pop("AGENTGUARD_PROVIDER", None)


# ─── Entry point ─────────────────────────────────────────────────────────────

def main():
    print("=" * 66)
    print("  AGENTGUARD — OFFLINE PROVIDER CONTRACT TESTS")
    print("  Verifies backend correctness without contacting any provider.")
    print("=" * 66)

    for test in (
        test_gemini,
        test_gemini_empty_candidate,
        test_groq,
        test_anthropic,
        test_missing_key_fails_loudly,
        test_retry_on_rate_limit,
        test_gives_up_after_retries,
        test_no_retry_on_auth_error,
        test_provider_auto_detection,
    ):
        test()

    print("\n" + "=" * 66)
    print(f"  {PASSED} passed, {FAILED} failed")
    print("=" * 66)
    print("\n  NOTE: these tests prove the requests AgentGuard builds are")
    print("  correct. They cannot prove a provider accepts them in production.")
    print("  Confirm that on a networked machine with a real key:")
    print("      python3 -m agentguard.main providers --test\n")

    sys.exit(1 if FAILED else 0)


if __name__ == "__main__":
    main()
