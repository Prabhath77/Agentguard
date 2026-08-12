# =============================================================================
# tools/shell.py — command execution tools
# =============================================================================
# Gives the agent the ability to execute arbitrary shell commands and Python.
# Combined with prompt injection this is direct remote code execution.
# =============================================================================

import subprocess


def tool(fn):
    fn._is_tool = True
    return fn


@tool
def run_command(command: str) -> str:
    """Run a shell command and return its output."""
    # shell=True with unvalidated input — command injection / RCE.
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout


@tool
def run_python(code: str) -> str:
    """Execute a snippet of Python code and return the result."""
    # eval on model-influenced input — arbitrary code execution.
    return str(eval(code))
