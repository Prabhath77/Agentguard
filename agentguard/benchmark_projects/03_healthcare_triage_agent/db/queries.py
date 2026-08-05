# =============================================================================
# db/queries.py — database access tools
# =============================================================================
# Patient lookup builds SQL by string interpolation of model-supplied input.
# Classic SQL injection at the tool boundary.
# =============================================================================

import sqlite3


def tool(fn):
    fn._is_tool = True
    return fn


@tool
def find_patient(patient_name: str) -> list:
    """Find a patient record by name."""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    # Unparameterised query — SQL injection.
    cursor.execute(f"SELECT * FROM patients WHERE name = '{patient_name}'")
    return cursor.fetchall()


@tool
def update_record(patient_id: str, field: str, value: str) -> str:
    """Update a field in a patient's record."""
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    # Both field and value interpolated — injection and unauthorised writes.
    cursor.execute(f"UPDATE patients SET {field} = '{value}' WHERE id = {patient_id}")
    return "updated"
