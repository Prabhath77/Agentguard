# =============================================================================
# parser.py — Agent Code Parser
# =============================================================================
# Extracts the components of an AI agent from source code:
#   - System prompts
#   - Tool/function definitions  
#   - Model configuration
#   - Memory/state mechanisms
#   - Imports (used to detect framework)
#
# Uses Python AST for structural parsing.  The LLM analyzer then takes
# these extracted components and reasons about vulnerabilities.
# =============================================================================

import ast
import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from pathlib import Path


@dataclass
class ToolDef:
    """A tool/function exposed to the agent."""
    name:        str
    description: str
    parameters:  Dict[str, Any]
    source_code: str
    line_start:  int
    line_end:    int
    decorators:  List[str] = field(default_factory=list)


@dataclass
class AgentManifest:
    """Everything we extracted from an agent codebase."""
    file_path:        str
    source_code:      str
    framework:        str                       # langchain | anthropic | openai | custom
    model:            Optional[str] = None
    system_prompt:    Optional[str] = None
    tools:            List[ToolDef] = field(default_factory=list)
    memory_uses:      List[str]    = field(default_factory=list)
    imports:          List[str]    = field(default_factory=list)
    raw_string_literals: List[str] = field(default_factory=list)


# ─── Framework detection ──────────────────────────────────────────────────────

FRAMEWORK_SIGNATURES = {
    "langchain": ["langchain", "langchain_core", "langchain_anthropic", "langchain_openai"],
    "anthropic": ["anthropic", "from anthropic"],
    "openai":    ["openai", "from openai"],
    "autogen":   ["autogen", "pyautogen"],
    "crewai":    ["crewai"],
}


def detect_framework(imports: List[str]) -> str:
    for fw, signatures in FRAMEWORK_SIGNATURES.items():
        for sig in signatures:
            if any(sig in imp for imp in imports):
                return fw
    return "custom"


# ─── Tool extraction ──────────────────────────────────────────────────────────

TOOL_DECORATORS = {"tool", "Tool", "function_tool", "register_tool"}


def is_tool_function(node: ast.FunctionDef) -> bool:
    """A function is a 'tool' if it's decorated with @tool, @Tool, or similar."""
    for dec in node.decorator_list:
        # @tool
        if isinstance(dec, ast.Name) and dec.id in TOOL_DECORATORS:
            return True
        # @tool(...)
        if isinstance(dec, ast.Call):
            if isinstance(dec.func, ast.Name) and dec.func.id in TOOL_DECORATORS:
                return True
            if isinstance(dec.func, ast.Attribute) and dec.func.attr in TOOL_DECORATORS:
                return True
    return False


def extract_function_params(node: ast.FunctionDef) -> Dict[str, Any]:
    """Pull parameter names and any annotations."""
    params = {}
    for arg in node.args.args:
        params[arg.arg] = {
            "annotation": ast.unparse(arg.annotation) if arg.annotation else None
        }
    return params


def extract_docstring(node: ast.FunctionDef) -> str:
    """Get the function docstring — this is often used as the tool description."""
    return ast.get_docstring(node) or ""


def get_decorator_names(node: ast.FunctionDef) -> List[str]:
    names = []
    for dec in node.decorator_list:
        if isinstance(dec, ast.Name):
            names.append(dec.id)
        elif isinstance(dec, ast.Call):
            if isinstance(dec.func, ast.Name):
                names.append(dec.func.id)
            elif isinstance(dec.func, ast.Attribute):
                names.append(dec.func.attr)
    return names


def extract_tool(node: ast.FunctionDef, source_lines: List[str]) -> ToolDef:
    """Build a ToolDef from a function node."""
    src = "\n".join(source_lines[node.lineno - 1 : node.end_lineno])
    return ToolDef(
        name        = node.name,
        description = extract_docstring(node),
        parameters  = extract_function_params(node),
        source_code = src,
        line_start  = node.lineno,
        line_end    = node.end_lineno or node.lineno,
        decorators  = get_decorator_names(node),
    )


# ─── System prompt extraction ─────────────────────────────────────────────────

SYSTEM_PROMPT_HINTS = [
    "system_prompt", "system_message", "SYSTEM_PROMPT", "SYSTEM_MESSAGE",
    "instructions", "INSTRUCTIONS"
]


def extract_system_prompt(tree: ast.Module) -> Optional[str]:
    """
    Walk the AST looking for variables named like a system prompt
    being assigned a string literal (or a multi-line string).
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and any(
                    h.lower() in target.id.lower() for h in SYSTEM_PROMPT_HINTS
                ):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        return node.value.value

        # Also catch dict-style: messages=[{"role": "system", "content": "..."}]
        if isinstance(node, ast.Dict):
            for k, v in zip(node.keys, node.values):
                if (isinstance(k, ast.Constant) and k.value == "role"
                        and isinstance(v, ast.Constant) and v.value == "system"):
                    # Find the matching "content" key
                    for k2, v2 in zip(node.keys, node.values):
                        if (isinstance(k2, ast.Constant) and k2.value == "content"
                                and isinstance(v2, ast.Constant) and isinstance(v2.value, str)):
                            return v2.value

    return None


# ─── Memory mechanism detection ───────────────────────────────────────────────

MEMORY_PATTERNS = [
    "ConversationBufferMemory", "ConversationSummaryMemory",
    "VectorStoreRetriever", "Chroma", "FAISS", "Pinecone",
    "messages_history", "conversation_history", "memory.save"
]


def detect_memory_usage(source_code: str) -> List[str]:
    found = []
    for pattern in MEMORY_PATTERNS:
        if pattern in source_code:
            found.append(pattern)
    return found


# ─── Model detection ──────────────────────────────────────────────────────────

MODEL_REGEX = re.compile(
    r'["\']'
    r'(claude-[a-z0-9\-]+|'
    r'gpt-[0-9\.\-a-z]+|'
    r'llama-?[0-9\.\-]+[a-z]*|'
    r'mistral-[a-z0-9\-]+|'
    r'gemini-[a-z0-9\.\-]+)'
    r'["\']',
    re.IGNORECASE
)


def detect_model(source_code: str) -> Optional[str]:
    m = MODEL_REGEX.search(source_code)
    return m.group(1) if m else None


# ─── Imports ──────────────────────────────────────────────────────────────────

def extract_imports(tree: ast.Module) -> List[str]:
    imports = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                imports.append(f"{module}.{alias.name}" if module else alias.name)
    return imports


# ─── String literals (for secret detection) ───────────────────────────────────

def extract_string_literals(tree: ast.Module, min_length: int = 10) -> List[str]:
    """Pull all string literals over a given length — used by secret scanner."""
    literals = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if len(node.value) >= min_length:
                literals.append(node.value)
    return literals


# ─── Main parse function ──────────────────────────────────────────────────────

def find_constructor_registered_tools(tree: ast.Module) -> Dict[str, str]:
    """
    Detect tools registered via LangChain constructor idioms rather than the
    @tool decorator, e.g.:

        Tool(name='GetUser', func=get_current_user, description="...")
        StructuredTool.from_function(func=get_transactions, name="...")
        Tool.from_function(get_current_user, "GetUser", "...")

    Returns {function_name: description}. The function name is what links the
    registration back to the def that implements it, so its body can be
    analysed; the description is taken from the constructor when present, since
    for these forms the description lives in the call, not a docstring.

    This matters for real-world code: much LangChain agent code — including the
    WithSecure DVLA reference target — predates or avoids the @tool decorator
    and uses these constructor forms exclusively.
    """
    registered: Dict[str, str] = {}
    TOOL_CTORS = {"Tool", "StructuredTool"}

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        # Is this a call to Tool(...), StructuredTool(...), or
        # Tool.from_function(...) / StructuredTool.from_function(...)?
        is_tool_ctor = False
        if isinstance(node.func, ast.Name) and node.func.id in TOOL_CTORS:
            is_tool_ctor = True
        elif isinstance(node.func, ast.Attribute):
            if (node.func.attr in {"from_function", "from_defaults"} and
                    isinstance(node.func.value, ast.Name) and
                    node.func.value.id in TOOL_CTORS):
                is_tool_ctor = True

        if not is_tool_ctor:
            continue

        func_name = None
        description = ""

        # Keyword form: func=..., description=...
        for kw in node.keywords:
            if kw.arg in ("func", "coroutine") and isinstance(kw.value, ast.Name):
                func_name = kw.value.id
            elif kw.arg == "description" and isinstance(kw.value, ast.Constant):
                description = str(kw.value.value)

        # Positional form: from_function(the_func, "name", "description")
        if func_name is None and node.args:
            first = node.args[0]
            if isinstance(first, ast.Name):
                func_name = first.id

        if func_name:
            registered[func_name] = description

    return registered


def parse_agent(file_path: str) -> AgentManifest:
    """
    Parse an agent source file and extract its manifest.
    This is what the analyzer consumes.
    """
    path   = Path(file_path)
    source = path.read_text(encoding="utf-8")
    tree   = ast.parse(source, filename=str(path))
    lines  = source.splitlines()

    # Extract everything
    imports     = extract_imports(tree)
    framework   = detect_framework(imports)
    sys_prompt  = extract_system_prompt(tree)
    model       = detect_model(source)
    memory      = detect_memory_usage(source)
    literals    = extract_string_literals(tree)

    tools: List[ToolDef] = []
    seen_tool_names = set()

    # (1) Decorator-declared tools: @tool, @Tool, @function_tool, etc.
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if is_tool_function(node):
                td = extract_tool(node, lines)
                if td.name not in seen_tool_names:
                    tools.append(td)
                    seen_tool_names.add(td.name)

    # (2) Constructor-registered tools: Tool(name=, func=), StructuredTool,
    #     Tool.from_function(...), etc. This is how much real LangChain code
    #     (including the WithSecure DVLA target) declares tools. Link each
    #     registration back to the function that implements it so its body can
    #     be analysed, and take the description from the constructor call.
    ctor_tools = find_constructor_registered_tools(tree)
    if ctor_tools:
        func_defs = {
            n.name: n for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        for func_name, description in ctor_tools.items():
            if func_name in seen_tool_names:
                continue
            impl = func_defs.get(func_name)
            if impl is not None:
                td = extract_tool(impl, lines)
                if description:
                    td.description = description
                tools.append(td)
                seen_tool_names.add(func_name)

    # (3) Structural fallback for agent code that uses an idiom we do not model
    #     explicitly. Broadened from the original (anthropic/custom only) to
    #     every framework, so unfamiliar or hand-rolled agent code is not
    #     silently skipped just because its declaration style is unusual.
    if not tools:
        ACTION_VERBS = [
            "send", "read", "write", "fetch", "delete", "create", "execute",
            "query", "list", "run", "update", "search", "retrieve", "get",
            "post", "call", "invoke", "return", "load", "save", "connect",
            "issue", "process", "lookup", "remove", "modify", "upload",
        ]
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                doc = (ast.get_docstring(node) or "").lower()
                looks_like_action = any(v in doc for v in ACTION_VERBS)
                is_public = not node.name.startswith("_")
                takes_input = len(node.args.args) > 0
                if looks_like_action or (
                    framework not in ("unknown", "custom")
                    and is_public and takes_input and doc
                ):
                    td = extract_tool(node, lines)
                    if td.name not in seen_tool_names:
                        tools.append(td)
                        seen_tool_names.add(td.name)

    return AgentManifest(
        file_path           = str(path),
        source_code         = source,
        framework           = framework,
        model               = model,
        system_prompt       = sys_prompt,
        tools               = tools,
        memory_uses         = memory,
        imports             = imports,
        raw_string_literals = literals
    )


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python parser.py <agent_file.py>")
        sys.exit(1)

    manifest = parse_agent(sys.argv[1])
    print(f"\n  File:      {manifest.file_path}")
    print(f"  Framework: {manifest.framework}")
    print(f"  Model:     {manifest.model}")
    print(f"  Tools:     {len(manifest.tools)}")
    for t in manifest.tools:
        print(f"    - {t.name} ({len(t.description)} char description)")
    print(f"  System prompt: {'YES' if manifest.system_prompt else 'NO'}")
    print(f"  Memory uses:   {manifest.memory_uses}")
