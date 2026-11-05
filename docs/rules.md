# Security Rule Engine

SecSkill rules are declared in YAML under `secskill/rules/`. Each rule contains:
- `id`: Unique identifier (e.g., `SEC-PY-001`)
- `name`: Human-readable summary
- `severity`: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`
- `cwe`: Standard Common Weakness Enumeration ID
- `patterns`: Regular expression or AST query matchers
