# SecSkill Rule Authoring Guide

This guide explains how security engineers and open-source contributors can define and contribute new security rules to SecSkill.

---

## 1. Rule Architecture & Schema

Rules are defined in YAML under `secskill/rules/<category>.yaml` (e.g., `python.yaml`, `javascript.yaml`, `java.yaml`, `secrets.yaml`). Every rule must be self-contained and specify detection patterns, data-flow boundaries, remediation advice, and positive/negative test fixtures.

### Required Fields

```yaml
rules:
  - id: SEC-089-SQLI                    # Unique ID: SEC-<CWE-NUMBER>-<SLUG>
    title: SQL Injection via Formatting  # Clear, concise human title
    cwe: CWE-89                         # MITRE CWE identifier
    owasp: A03:2021-Injection           # OWASP Top 10 (2021) category
    severity: CRITICAL                  # CRITICAL | HIGH | MEDIUM | LOW | INFORMATIONAL
    languages:                          # Supported target languages
      - python
    patterns:                           # Regex or AST pattern list
      - 'cursor\.execute\s*\(\s*f["\']'
      - 'cursor\.execute\s*\([^,)]*%\s*'
      - 'cursor\.execute\s*\([^,)]*\.format\s*\('
    dataflow:                           # Taint analysis markers
      sources:
        - request.args
        - request.form
        - request.json
        - request.values
      sinks:
        - cursor.execute
        - connection.execute
        - db.session.execute
    remediation:
      description: Use parameterized queries with bound placeholders. Never format user strings into SQL queries.
      vulnerable_example: |
        cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
      secure_example: |
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    references:
      - https://owasp.org/www-community/attacks/SQL_Injection
      - https://cwe.mitre.org/data/definitions/89.html
    test_cases:
      vulnerable:
        code: |
          def query_user(user_id):
              cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
        expected_finding: true
        expected_cwe: CWE-89
      secure:
        code: |
          def query_user(user_id):
              cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        expected_finding: false
```

---

## 2. Worked Example: SQL Injection Rule (SEC-089-SQLI)

Below is the complete, canonical implementation of the SQL Injection rule for Python:

```yaml
  - id: SEC-089-SQLI
    title: "SQL Injection via String Concatenation or Formatting"
    cwe: "CWE-89"
    owasp: "A03:2021-Injection"
    ssdf: "PW.5.1"
    severity: "CRITICAL"
    confidence: 0.90
    languages:
      - python
    patterns:
      - 'cursor\.execute\s*\(\s*f["\']'
      - 'cursor\.execute\s*\([^\n)]*\%'
      - 'cursor\.execute\s*\([^\n)]*\.format\('
      - 'cursor\.execute\s*\([^\n)]*\+\s*[a-zA-Z_]'
    dataflow:
      sources:
        - "request.args"
        - "request.form"
        - "request.json"
        - "request.GET"
        - "request.POST"
      sinks:
        - "cursor.execute"
        - "connection.execute"
        - "db.session.execute"
    remediation:
      description: "Replace string interpolation with query parameter binding supported by the database driver."
      vulnerable_example: |
        cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
      secure_example: |
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    references:
      - "https://cwe.mitre.org/data/definitions/89.html"
      - "https://owasp.org/Top10/A03_2021-Injection/"
    test_cases:
      vulnerable:
        code: |
          user_id = request.args.get("id")
          cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
        expected_finding: true
        expected_cwe: "CWE-89"
      secure:
        code: |
          user_id = request.args.get("id")
          cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        expected_finding: false
```

---

## 3. Contributing Checklist

When submitting a pull request adding or modifying a rule:
1. Ensure the Rule ID follows `SEC-<CWE>-<DESCRIPTOR>` uppercase format.
2. Confirm both `vulnerable` and `secure` test samples are present in the rule definition.
3. Validate that the rule triggers on the vulnerable snippet and does NOT trigger on the secure snippet.
4. Run `pytest tests/` to confirm that benchmark test suites pass.
5. Provide references from MITRE CWE and OWASP Top 10.

