# =============================================================================
# config.py — AgentGuard Configuration
# =============================================================================
# AgentGuard runs on FREE LLM providers by default. No credit card required.
#
#   DEFAULT:  Gemini (Google AI Studio)
#             Free key: https://aistudio.google.com/apikey
#             export GEMINI_API_KEY="AIza..."
#
#   ALT:      Groq (fastest inference, open models)
#             Free key: https://console.groq.com/keys
#             export GROQ_API_KEY="gsk_..."
#             export AGENTGUARD_PROVIDER=groq
#
#   ALT:      OpenRouter (routes to NVIDIA Nemotron 3 Ultra's free tier by
#             default — a large, agent-optimised, independently-trained
#             model, useful as a genuinely different third option rather
#             than another Google/Groq-adjacent choice)
#             Free key: https://openrouter.ai/keys
#             export OPENROUTER_API_KEY="sk-or-..."
#             export AGENTGUARD_PROVIDER=openrouter
#             NOTE: the free-tier model slug (":free" suffix) is
#             rate-limited by OpenRouter same as any other free tier —
#             this is not an unlimited fallback, just an independent one.
#
# Provider is auto-detected from whichever key is present, so in most cases
# exporting one key is the only setup step. Set AGENTGUARD_PROVIDER to force
# a specific backend.
# =============================================================================

import os

# ─── Raw keys from the environment ───────────────────────────────────────────
GEMINI_API_KEY     = os.environ.get("GEMINI_API_KEY",     "")
GROQ_API_KEY       = os.environ.get("GROQ_API_KEY",       "")
OPENROUTER_API_KEY = os.environ.get("OPENROUTER_API_KEY", "")
OPENAI_API_KEY     = os.environ.get("OPENAI_API_KEY",     "")
ANTHROPIC_API_KEY  = os.environ.get("ANTHROPIC_API_KEY",  "")


def _auto_detect_provider() -> str:
    """
    Pick a provider based on which key is actually set.
    Preference order puts the free providers first, and Gemini ahead of the
    rest because its far larger context window suits whole-project scanning.
    OpenRouter (Nemotron) sits after Groq: both are free-tier fallbacks, but
    Groq has been the more heavily-tested fallback across this project's
    evaluation so it keeps priority as the second choice.
    """
    if OPENROUTER_API_KEY:
        return "openrouter"
    if GEMINI_API_KEY:
        return "gemini"
    if GROQ_API_KEY:
        return "groq"
    if ANTHROPIC_API_KEY:
        return "anthropic"
    if OPENAI_API_KEY:
        return "openai"
    return "openrouter"   # default even with no key, so error messages are clear


LLM_PROVIDER = os.environ.get("AGENTGUARD_PROVIDER", "").strip().lower() \
               or _auto_detect_provider()

# ─── Per-provider endpoints and models ───────────────────────────────────────
GEMINI_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"
GEMINI_MODEL    = os.environ.get("GEMINI_MODEL", "gemini-flash-latest")
# NOTE: "gemini-flash-latest" is an alias Google maintains that always points
# at their current recommended Flash model, so this default should not go
# stale the way a dated version number (e.g. "gemini-2.5-flash") eventually
# does. If it ever does 404, list the models your key can see and override:
#   export GEMINI_MODEL="whatever-name-is-current"
# See README.md, "If the Gemini model 404s" for the exact command.

GROQ_BASE_URL   = "https://api.groq.com/openai/v1"
GROQ_MODEL      = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
OPENROUTER_MODEL    = os.environ.get(
    "OPENROUTER_MODEL", "nvidia/nemotron-3-ultra-550b-a55b:free"
)
# NOTE: the ":free" suffix is load-bearing — it is a distinct routing slug
# from "nvidia/nemotron-3-ultra-550b-a55b" (no suffix), which is the paid,
# higher-throughput variant. Dropping the suffix silently starts billing.

OPENAI_BASE_URL = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
OPENAI_MODEL    = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")

ANTHROPIC_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")

# ─── Resolved active settings (imported by the rest of the codebase) ─────────
if LLM_PROVIDER == "gemini":
    LLM_API_KEY, LLM_BASE_URL, LLM_MODEL = GEMINI_API_KEY, GEMINI_BASE_URL, GEMINI_MODEL
elif LLM_PROVIDER == "groq":
    LLM_API_KEY, LLM_BASE_URL, LLM_MODEL = GROQ_API_KEY, GROQ_BASE_URL, GROQ_MODEL
elif LLM_PROVIDER == "openrouter":
    LLM_API_KEY, LLM_BASE_URL, LLM_MODEL = OPENROUTER_API_KEY, OPENROUTER_BASE_URL, OPENROUTER_MODEL
elif LLM_PROVIDER == "anthropic":
    LLM_API_KEY, LLM_BASE_URL, LLM_MODEL = ANTHROPIC_API_KEY, None, ANTHROPIC_MODEL
elif LLM_PROVIDER == "openai":
    LLM_API_KEY, LLM_BASE_URL, LLM_MODEL = OPENAI_API_KEY, OPENAI_BASE_URL, OPENAI_MODEL
else:
    raise ValueError(
        f"Unknown AGENTGUARD_PROVIDER '{LLM_PROVIDER}'. "
        f"Valid options: gemini, groq, openrouter, openai, anthropic"
    )

MAX_TOKENS = 4096

# ─── Scanner settings ────────────────────────────────────────────────────────
ENABLE_LLM_ANALYSIS  = True
ENABLE_GRAPH_BUILD   = True
ENABLE_DYNAMIC_TESTS = False

# ─── Project scanning (folders and zips) ─────────────────────────────────────
# Directories skipped when walking a project tree. These hold dependencies and
# build artefacts, never the agent code under assessment.
PROJECT_IGNORE_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", ".pytest_cache", ".mypy_cache",
    ".ruff_cache", ".tox", "node_modules", "venv", ".venv", "env", ".env",
    "site-packages", "dist", "build", ".eggs", ".idea", ".vscode",
    "reports", ".ipynb_checkpoints",
}
PROJECT_MAX_FILES     = 400      # safety valve on very large repositories
PROJECT_MAX_FILE_SIZE = 1_000_000  # bytes; skip anything larger than ~1 MB

# ─── Output settings ─────────────────────────────────────────────────────────
REPORT_DIR        = "reports"
GENERATE_MARKDOWN = True
GENERATE_JSON     = True
GENERATE_HTML     = False

# ─── Severity thresholds ─────────────────────────────────────────────────────
SEVERITY_LEVELS = {
    "CRITICAL": 9.0,
    "HIGH":     7.0,
    "MEDIUM":   4.0,
    "LOW":      1.0,
    "INFO":     0.0,
}
