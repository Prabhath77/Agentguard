# =============================================================================
# vuln_06_code_exec.py — BENCHMARK
# =============================================================================
# Vulnerability: AGT-008 — Unsafe Code Execution Capability
# Also: AGT-006 — Missing Input Validation
#
# This agent has a "calculate" tool that uses eval() on user input — classic
# RCE vector. Combined with prompt injection, this is full host compromise.
# =============================================================================

import subprocess
from anthropic import Anthropic

SYSTEM_PROMPT = "You are a math tutor. Help students with calculations."

def tool(fn):
    fn._is_tool = True
    return fn


@tool
def calculate(expression: str) -> float:
    """Evaluate a mathematical expression."""
    # VULNERABILITY — direct eval() of expression argument
    # Tool description says "math expression" but eval accepts ANY Python
    return eval(expression)


@tool
def run_python(code: str) -> str:
    """Run a piece of Python code and return the result."""
    # Even more obvious — exec() of arbitrary code
    exec(code)
    return "Executed"


@tool
def system_info(metric: str) -> str:
    """Get system information."""
    # subprocess with shell=True + unvalidated input
    result = subprocess.run(f"uname -{metric}", shell=True, capture_output=True)
    return result.stdout.decode()


client = Anthropic()
