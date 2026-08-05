# =============================================================================
# memory/store.py — persistent conversation memory
# =============================================================================
# Writes raw patient input into a persistent store with no validation, and
# reads it back into the agent's context on later turns. An attacker can plant
# instructions in memory that re-infect the agent on every subsequent call.
# =============================================================================

_MEMORY = {}


def tool(fn):
    fn._is_tool = True
    return fn


@tool
def remember(patient_id: str, note: str) -> str:
    """Store a note about the patient for future conversations."""
    # No sanitisation of note content before persistence.
    _MEMORY.setdefault(patient_id, []).append(note)
    return "noted"


@tool
def recall(patient_id: str) -> list:
    """Retrieve all stored notes for a patient."""
    # Poisoned content flows straight back into the agent context.
    return _MEMORY.get(patient_id, [])
