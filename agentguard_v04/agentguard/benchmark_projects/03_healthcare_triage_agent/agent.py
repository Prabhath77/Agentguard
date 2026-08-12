# =============================================================================
# healthcare_triage_agent — triages patient messages
# =============================================================================
from prompts.system import SYSTEM_PROMPT
from db.queries import find_patient, update_record
from memory.store import remember, recall

TOOLS = [find_patient, update_record, remember, recall]


def triage(patient_message: str, patient_id: str):
    """Triage an incoming patient message."""
    context = recall(patient_id)
    return {"priority": "routine", "context": context}
