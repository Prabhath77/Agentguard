# =============================================================================
# sandbox_runner.py — Phase 4: Sandboxed Exploit Execution
# =============================================================================
# Runs generated exploit scripts in a heavily isolated environment.
#
# Defence-in-depth layers:
#   1. Subprocess (separate process)
#   2. Strict timeout (default 10s, hard kill)
#   3. Resource limits (CPU, memory, file size, no fork bombs)
#   4. Temporary working directory (scoped, deleted after)
#   5. Cleansed environment (no real API keys, no parent env vars)
#   6. Optional Docker containerisation for hardest isolation
#   7. Captured stdout/stderr (no propagation to terminal)
#   8. Multi-signal result classification
#
# The runner DOES NOT trust exit codes alone. It analyses:
#   - stdout for explicit AgentGuard flags
#   - stderr for crash/sandbox-violation indicators
#   - timeout / exit code
#   - elapsed time (cheap but not authoritative)
# =============================================================================

import os
import sys
import shutil
import tempfile
import subprocess
import resource
import time
from dataclasses import dataclass, field
from typing import List, Optional
from pathlib import Path

from .exploit_generator import (
    Exploit, FLAG_REACHED, FLAG_TRIGGERED, FLAG_EXTRACTED, ALL_FLAGS
)


# ─── Sandbox configuration ───────────────────────────────────────────────────

DEFAULT_TIMEOUT_SEC = 10
MAX_OUTPUT_BYTES    = 64 * 1024     # cap stdout/stderr capture
MEM_LIMIT_BYTES     = 256 * 1024 * 1024   # 256 MB
CPU_LIMIT_SEC       = 8
FILE_SIZE_LIMIT     = 5 * 1024 * 1024     # 5 MB
MAX_PROCESSES       = 50


# ─── Result data class ───────────────────────────────────────────────────────

@dataclass
class SandboxResult:
    """Structured result of running one exploit in the sandbox."""
    exploit_strategy: str
    success_level:    str             # "EXTRACTED" | "TRIGGERED" | "REACHED" | "NONE"
    confidence:       float           # 0.0 to 1.0
    timed_out:        bool = False
    crashed:          bool = False
    elapsed_sec:      float = 0.0
    exit_code:        int   = 0
    stdout:           str   = ""
    stderr:           str   = ""
    flags_seen:       List[str] = field(default_factory=list)
    benign_clean:     Optional[bool] = None    # True = differential test passed
    notes:            List[str] = field(default_factory=list)
    used_docker:      bool = False    # True = ran in the Docker-isolated path for
                                        # this specific execution, False = subprocess
                                        # fallback. Recorded per-run, not assumed from
                                        # environment, so this is genuine evidence
                                        # rather than an inferred claim.


# ─── Pre-exec hook for resource limits ───────────────────────────────────────

def _apply_limits():
    """
    Run inside the child process before exec.
    Sets POSIX resource limits to constrain what the exploit can do.
    These are kernel-level — no Python escape.
    """
    # CPU time limit
    try:
        resource.setrlimit(resource.RLIMIT_CPU, (CPU_LIMIT_SEC, CPU_LIMIT_SEC))
    except (ValueError, OSError):
        pass

    # Memory limit (address space) — may not work on macOS, but harmless
    try:
        resource.setrlimit(resource.RLIMIT_AS, (MEM_LIMIT_BYTES, MEM_LIMIT_BYTES))
    except (ValueError, OSError):
        pass

    # Max file size the process can create
    try:
        resource.setrlimit(resource.RLIMIT_FSIZE, (FILE_SIZE_LIMIT, FILE_SIZE_LIMIT))
    except (ValueError, OSError):
        pass

    # Max number of processes — prevent fork bombs
    try:
        resource.setrlimit(resource.RLIMIT_NPROC, (MAX_PROCESSES, MAX_PROCESSES))
    except (ValueError, OSError):
        pass

    # Become a new session leader — prevents some signal escapes
    try:
        os.setsid()
    except OSError:
        pass


# ─── Cleansed environment ────────────────────────────────────────────────────

DANGEROUS_ENV_KEYS = {
    "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "SLACK_TOKEN",
    "GOOGLE_API_KEY", "AZURE_API_KEY", "STRIPE_KEY",
    "DATABASE_URL", "REDIS_URL", "MONGODB_URI",
}


def _cleansed_env(workdir: str) -> dict:
    """Build a minimal environment for the sandbox — no secrets leak through."""
    safe = {
        "PATH":     "/usr/local/bin:/usr/bin:/bin",
        "HOME":     workdir,
        "TMPDIR":   workdir,
        "PYTHONUNBUFFERED": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "AGENTGUARD_SANDBOX": "1",
    }
    # Only forward LANG/LC if present (UTF-8 needed)
    for k in ("LANG", "LC_ALL"):
        if k in os.environ:
            safe[k] = os.environ[k]
    return safe


# ─── Output trimming ─────────────────────────────────────────────────────────

def _truncate(data: str, limit: int = MAX_OUTPUT_BYTES) -> str:
    if len(data) <= limit:
        return data
    return data[:limit] + f"\n[... TRUNCATED at {limit} bytes ...]"


# ─── Flag classification ─────────────────────────────────────────────────────

def _classify_success(stdout: str) -> tuple[str, List[str]]:
    """
    Examine stdout for AgentGuard flags. Returns (success_level, flags_seen).
    The hierarchy is EXTRACTED > TRIGGERED > REACHED > NONE.
    """
    flags_seen = [f for f in ALL_FLAGS if f in stdout]
    if FLAG_EXTRACTED in stdout:
        return "EXTRACTED", flags_seen
    if FLAG_TRIGGERED in stdout:
        return "TRIGGERED", flags_seen
    if FLAG_REACHED in stdout:
        return "REACHED", flags_seen
    return "NONE", flags_seen


# ─── Differential test — benign run must NOT trigger flags ───────────────────

def _benign_clean(benign_stdout: str) -> bool:
    """
    Returns True if the benign run did NOT trip the trigger or extract flag.
    A reached flag is OK (just means the tool loaded), but trigger/extract
    in benign mode means our exploit isn't actually exploiting anything
    specific — it's tripping on benign input.
    """
    return FLAG_TRIGGERED not in benign_stdout and FLAG_EXTRACTED not in benign_stdout


# ─── Confidence scoring ──────────────────────────────────────────────────────

def _score_confidence(success_level: str, benign_clean: Optional[bool],
                       crashed: bool, timed_out: bool) -> float:
    """
    Compute a 0–1 confidence score from sandbox signals.
    """
    if crashed or timed_out:
        return 0.0
    base = {
        "EXTRACTED": 0.95,
        "TRIGGERED": 0.75,
        "REACHED":   0.30,
        "NONE":      0.0,
    }[success_level]

    # Bonus for differential test passing
    if benign_clean is True and base > 0.0:
        base = min(1.0, base + 0.05)
    # Penalty if differential test failed (benign also tripped)
    elif benign_clean is False and base > 0.0:
        base = max(0.0, base * 0.6)

    return round(base, 2)


# ─── Single sandbox execution ────────────────────────────────────────────────

def _run_in_sandbox(code: str, agent_path: str,
                     timeout: int = DEFAULT_TIMEOUT_SEC) -> tuple[str, str, int, bool, bool, float, bool]:
    """
    Execute a single Python script in the sandbox.
    Prefers Docker if available; falls back to subprocess with resource limits.
    Returns: (stdout, stderr, exit_code, timed_out, crashed, elapsed_sec, used_docker)
    """
    # ── Try Docker first ──
    try:
        from .docker_sandbox import run_in_docker, docker_available
        if docker_available():
            r = run_in_docker(code, agent_path, timeout)
            if r.used_docker:
                return (_truncate(r.stdout), _truncate(r.stderr), r.exit_code,
                        r.timed_out, r.crashed, r.elapsed_sec, True)
    except ImportError:
        pass

    # ── Subprocess fallback (with resource limits) ──
    workdir   = tempfile.mkdtemp(prefix="agentguard_sandbox_")
    script_p  = Path(workdir) / "exploit.py"
    script_p.write_text(code)

    agent_p = Path(agent_path)
    if agent_p.exists():
        sandboxed_agent = Path(workdir) / agent_p.name
        shutil.copy2(agent_p, sandboxed_agent)
        # Quote-style-agnostic rewrite — see docker_sandbox._rewrite_quoted_path
        # for why a plain repr()-based replace silently fails whenever the
        # generating code quotes the path with double quotes instead of the
        # single quotes Python's repr() defaults to.
        from .docker_sandbox import _rewrite_quoted_path
        new_code = _rewrite_quoted_path(code, agent_path, str(sandboxed_agent))
        script_p.write_text(new_code)

    env = _cleansed_env(workdir)

    timed_out  = False
    crashed    = False
    exit_code  = 0
    stdout     = ""
    stderr     = ""

    start = time.monotonic()
    try:
        proc = subprocess.run(
            [sys.executable, "-I", str(script_p)],
            cwd        = workdir,
            env        = env,
            capture_output = True,
            timeout    = timeout,
            preexec_fn = _apply_limits if os.name == "posix" else None,
        )
        stdout    = proc.stdout.decode("utf-8", errors="replace")
        stderr    = proc.stderr.decode("utf-8", errors="replace")
        exit_code = proc.returncode

    except subprocess.TimeoutExpired as e:
        timed_out = True
        stdout = (e.stdout or b"").decode("utf-8", errors="replace")
        stderr = (e.stderr or b"").decode("utf-8", errors="replace")
        stderr += "\n[AGENTGUARD_SANDBOX] TIMEOUT — process killed."

    except Exception as e:
        crashed = True
        stderr  = f"[AGENTGUARD_SANDBOX] sandbox failure: {e}"

    finally:
        elapsed = time.monotonic() - start
        try:
            shutil.rmtree(workdir, ignore_errors=True)
        except Exception:
            pass

    return (_truncate(stdout), _truncate(stderr), exit_code,
            timed_out, crashed, round(elapsed, 3), False)


# ─── Public API ──────────────────────────────────────────────────────────────

def _with_dependency_shim(code: str) -> str:
    """
    Prepend the missing-dependency shim to an exploit script.

    Agent code under assessment imports libraries the scanning machine does not
    have (anthropic, langchain, a client's private packages). Installing a
    target's entire dependency tree before scanning it is unrealistic, and for
    untrusted client code it is unsafe. The shim stubs only genuinely absent
    modules, so real installed packages still behave normally.

    Applied here rather than inside individual exploit templates so that every
    execution path benefits — including LLM-generated exploits, which are
    written at runtime and cannot be patched in advance.
    """
    if not code or "_AGFinder" in code:
        return code                      # already shimmed
    from .exploit_generator import DEPENDENCY_SHIM
    return DEPENDENCY_SHIM + "\n" + code


def run_exploit(exploit: Exploit, agent_path: str,
                run_benign: bool = True,
                timeout: int = DEFAULT_TIMEOUT_SEC) -> SandboxResult:
    """
    Run an exploit and (optionally) its benign counterpart.
    Returns a structured SandboxResult.
    """
    # ── Malicious run ─────────────────────────────────────────────────────────
    stdout, stderr, exit_code, timed_out, crashed, elapsed, used_docker = _run_in_sandbox(
        _with_dependency_shim(exploit.code), agent_path, timeout
    )
    success_level, flags_seen = _classify_success(stdout)
    print(f"      [Sandbox: {'Docker (isolated container)' if used_docker else 'subprocess (resource-limited, NOT filesystem/network isolated)'}]")

    # ── Benign run for differential test ─────────────────────────────────────
    benign_clean: Optional[bool] = None
    notes: List[str] = []

    if run_benign and exploit.benign_code and "no benign comparison" not in exploit.benign_code:
        b_stdout, _, _, b_timeout, b_crash, _, _ = _run_in_sandbox(
            _with_dependency_shim(exploit.benign_code), agent_path, timeout
        )
        if b_timeout or b_crash:
            notes.append("Benign run failed — differential test inconclusive.")
            benign_clean = None
        else:
            benign_clean = _benign_clean(b_stdout)
            if benign_clean is False:
                notes.append("WARNING: benign input also triggered flags. "
                              "Possible false positive in exploit.")
    else:
        notes.append("Differential test skipped (no benign code or N/A).")

    # ── Confidence score ─────────────────────────────────────────────────────
    confidence = _score_confidence(success_level, benign_clean, crashed, timed_out)

    return SandboxResult(
        exploit_strategy = exploit.strategy,
        success_level    = success_level,
        confidence       = confidence,
        timed_out        = timed_out,
        crashed          = crashed,
        elapsed_sec      = elapsed,
        exit_code        = exit_code,
        stdout           = stdout,
        stderr           = stderr,
        flags_seen       = flags_seen,
        benign_clean     = benign_clean,
        notes            = notes,
        used_docker      = used_docker,
    )
