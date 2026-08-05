# =============================================================================
# tools/summarise.py — pure text transformation (safe)
# =============================================================================


def tool(fn):
    fn._is_tool = True
    return fn


@tool
def summarise_text(text: str, max_sentences: int = 3) -> str:
    """Summarise a block of text to at most max_sentences sentences."""
    # Pure, side-effect-free string handling. No I/O, no external calls.
    if not isinstance(text, str):
        raise ValueError("text must be a string")
    sentences = text.split(".")
    return ". ".join(s.strip() for s in sentences[:max_sentences] if s.strip())
