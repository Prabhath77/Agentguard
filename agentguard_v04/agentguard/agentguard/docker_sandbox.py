# =============================================================================
# docker_sandbox.py — Docker-Based Exploit Execution
# =============================================================================
# Replaces the subprocess sandbox with a hardened Docker container when
# Docker is available on the host. Falls back to subprocess otherwise.
#
# Docker settings used:
#   --rm                       container deleted after run
#   --network=none             NO network access at all
#   --read-only                root filesystem is read-only
#   --tmpfs /tmp:size=64m      writable /tmp only, capped
#   --cap-drop=ALL             no Linux capabilities
#   --security-opt=...         no privilege escalation, no ptrace
#   --memory=256m              hard memory cap
#   --cpus=1.0                 one CPU core max
#   --pids-limit=64            no fork bombs
#   --user=nobody              non-root user inside container
#
# Even if the AI writes destructive code, it can:
#   - Not reach the internet
#   - Not write outside /tmp (cleared on exit)
#   - Not consume more than 256MB / 1 CPU
#   - Not escalate privileges
#   - Not fork bomb
# =============================================================================

import os
import re
import sys
import time
import shutil
import tempfile
import subprocess
from pathlib import Path
from dataclasses import dataclass
from typing import Optional


# ─── Capability detection ────────────────────────────────────────────────────

_docker_available: Optional[bool] = None


def docker_available() -> bool:
    """Cached check — is Docker installed and runnable?"""
    global _docker_available
    if _docker_available is not None:
        return _docker_available
    try:
        r = subprocess.run(
            ["docker", "--version"],
            capture_output=True, timeout=5
        )
        if r.returncode != 0:
            _docker_available = False
            return False
        # Also check we can actually run containers
        r2 = subprocess.run(
            ["docker", "ps"],
            capture_output=True, timeout=5
        )
        _docker_available = (r2.returncode == 0)
        return _docker_available
    except (FileNotFoundError, subprocess.TimeoutExpired):
        _docker_available = False
        return False


# ─── Image management ────────────────────────────────────────────────────────

SANDBOX_IMAGE = "agentguard-sandbox:latest"
SANDBOX_DOCKERFILE = """FROM python:3.11-slim
RUN useradd -m -u 1000 sandbox
RUN pip install --no-cache-dir requests
USER sandbox
WORKDIR /sandbox
"""


_sandbox_build_failed: bool = False


def ensure_sandbox_image() -> bool:
    """Build the sandbox image if it doesn't exist. Returns True on success."""
    global _sandbox_build_failed
    if not docker_available():
        return False
    if _sandbox_build_failed:
        # We already tried and failed this process — don't retry a build that
        # will fail again for the same reason (e.g. a deprecated legacy
        # builder). Silently fall back to the subprocess sandbox instead.
        return False

    # Check if image exists
    r = subprocess.run(
        ["docker", "image", "inspect", SANDBOX_IMAGE],
        capture_output=True, timeout=10
    )
    if r.returncode == 0:
        return True

    # Build it
    print(f"[Docker] Building sandbox image {SANDBOX_IMAGE} (one-time setup)...")
    build_dir = tempfile.mkdtemp(prefix="agentguard_build_")
    try:
        Path(build_dir, "Dockerfile").write_text(SANDBOX_DOCKERFILE)
        r = subprocess.run(
            ["docker", "build", "-t", SANDBOX_IMAGE, build_dir],
            capture_output=True, timeout=180
        )
        if r.returncode != 0:
            print(f"[Docker] Build failed: {r.stderr.decode()[:200]}")
            print(f"[Docker] Falling back to subprocess sandbox for this run.")
            _sandbox_build_failed = True
            return False
        return True
    finally:
        shutil.rmtree(build_dir, ignore_errors=True)


# ─── Execution ──────────────────────────────────────────────────────────────

@dataclass
class DockerResult:
    stdout:      str
    stderr:      str
    exit_code:   int
    timed_out:   bool
    crashed:     bool
    elapsed_sec: float
    used_docker: bool


def _rewrite_quoted_path(code: str, old_path: str, new_path: str) -> str:
    """
    Replace old_path with new_path inside a Python source string, regardless
    of whether the source quoted it with single or double quotes.

    A plain code.replace(repr(old_path), repr(new_path)) only matches if the
    quote style in the generated code happens to match Python's repr()
    default (single quotes). AI-generated exploit code frequently uses
    double quotes instead, in which case that replace silently does nothing
    — the script keeps referencing the original, sandbox-inaccessible path,
    and fails before printing anything. This matches the path wrapped in
    EITHER quote character and preserves whichever one the source used.
    """
    escaped = re.escape(old_path)
    pattern = rf"""(['"]){escaped}\1"""
    return re.sub(pattern, lambda m: f"{m.group(1)}{new_path}{m.group(1)}", code)


def run_in_docker(script_code: str, agent_file_path: Optional[str] = None,
                   timeout: int = 10) -> DockerResult:
    """
    Run a script in a hardened Docker container.
    If Docker isn't available, returns a result with used_docker=False
    and the caller falls back to subprocess.
    """
    if not docker_available() or not ensure_sandbox_image():
        return DockerResult(
            stdout="", stderr="[Docker unavailable]",
            exit_code=-1, timed_out=False, crashed=False,
            elapsed_sec=0.0, used_docker=False,
        )

    # Prep host directory that gets mounted into container
    host_dir = tempfile.mkdtemp(prefix="agentguard_dockermount_")
    try:
        Path(host_dir, "exploit.py").write_text(script_code)

        # If there's an agent file the exploit needs, copy it into the mount
        if agent_file_path and Path(agent_file_path).exists():
            sandboxed_agent_name = Path(agent_file_path).name
            shutil.copy2(agent_file_path,
                          Path(host_dir, sandboxed_agent_name))
            # Rewrite the script's path reference to point inside the
            # container. A plain repr()-based replace only matches if the
            # generating code happened to quote the path with single quotes
            # (Python's repr() default) — but AI-generated exploit code just
            # as often uses double quotes, in which case that replace would
            # silently do nothing, and the script would try to load the file
            # from its original (now Docker-inaccessible) host path, failing
            # before printing anything. This regex matches the path wrapped
            # in EITHER quote style and preserves whichever one was used.
            updated = _rewrite_quoted_path(
                script_code, agent_file_path, f"/sandbox/{sandboxed_agent_name}"
            )
            Path(host_dir, "exploit.py").write_text(updated)

        docker_args = [
            "docker", "run", "--rm",
            "--network=none",
            "--read-only",
            "--tmpfs", "/tmp:size=64m,mode=1777",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--memory=256m",
            "--cpus=1.0",
            "--pids-limit=64",
            "--user=1000:1000",
            "-v", f"{host_dir}:/sandbox:ro",
            "-w", "/sandbox",
            "--env", "PYTHONUNBUFFERED=1",
            "--env", "PYTHONDONTWRITEBYTECODE=1",
            "--env", "AGENTGUARD_SANDBOX=docker",
            SANDBOX_IMAGE,
            "python", "-I", "/sandbox/exploit.py",
        ]

        start = time.monotonic()
        try:
            proc = subprocess.run(
                docker_args,
                capture_output=True,
                timeout=timeout + 5,   # extra grace for docker startup
            )
            elapsed = time.monotonic() - start
            return DockerResult(
                stdout      = proc.stdout.decode("utf-8", errors="replace"),
                stderr      = proc.stderr.decode("utf-8", errors="replace"),
                exit_code   = proc.returncode,
                timed_out   = False,
                crashed     = False,
                elapsed_sec = round(elapsed, 3),
                used_docker = True,
            )
        except subprocess.TimeoutExpired as e:
            # Kill the container by name (we'd need to track it for clean kill;
            # for now rely on Docker's own resource caps to limit damage)
            return DockerResult(
                stdout      = (e.stdout or b"").decode("utf-8", errors="replace"),
                stderr      = (e.stderr or b"").decode("utf-8", errors="replace") + "\n[TIMEOUT]",
                exit_code   = -1,
                timed_out   = True,
                crashed     = False,
                elapsed_sec = round(time.monotonic() - start, 3),
                used_docker = True,
            )

    except Exception as e:
        return DockerResult(
            stdout="", stderr=f"Docker sandbox crashed: {e}",
            exit_code=-1, timed_out=False, crashed=True,
            elapsed_sec=0.0, used_docker=True,
        )

    finally:
        shutil.rmtree(host_dir, ignore_errors=True)
