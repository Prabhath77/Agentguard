# Tool Comparison — AgentGuard vs Bandit vs Semgrep

## Precision / Recall / F1 / Runtime

| Tool | Precision | Recall | F1 | Time (s) | AGT classes covered |
|------|-----------|--------|----|----------|--------------------|
| AgentGuard | 0.773 | 1.000 | 0.872 | 0.04 | 9/10 |
| Bandit | 1.000 | 0.353 | 0.522 | 0.83 | 3/10 |
| Semgrep | 0.833 | 0.294 | 0.435 | 18.93 | 2/10 |

## Agent Top 10 coverage

Whether each tool can detect the vulnerability class **at all**, even generously mapping its generic rules onto the taxonomy.

| Class | AgentGuard | Bandit | Semgrep |
|-------|-----------|--------|---------|
| AGT-001 | yes | no | no |
| AGT-002 | yes | no | no |
| AGT-003 | yes | no | no |
| AGT-004 | yes | no | no |
| AGT-005 | yes | no | no |
| AGT-006 | yes | yes | yes |
| AGT-007 | yes | yes | no |
| AGT-008 | yes | yes | yes |
| AGT-009 | yes | no | no |
| AGT-010 | no | no | no |

The agent-specific classes — AGT-001 (excessive permissions), AGT-002 (prompt injection), AGT-003 (system-prompt leakage), AGT-004 (unsafe tool chaining), AGT-005 (memory poisoning), AGT-010 (excessive agency) — are the ones general SAST tools cannot express, and are the reason an agent-specific scanner is needed.
