---
name: secpatch
description: "Instructs the agent to pick all High and Critical findings, generate patches, and verify them with secskill_verify_patch. Also triggered by the /secpatch slash command."
metadata:
  icon: healing
---

# /secpatch: Verified Remediation of High & Critical Findings

Picks up `CRITICAL` and `HIGH` security vulnerabilities, crafts deterministic defense-in-depth mitigations, and runs differential patch verification via `secskill_verify_patch` to guarantee zero regressions.

## Execution Procedure

1. **Vulnerability Discovery & Triage**:
   - Check if a recent scan or SARIF report exists, or run `secskill_scan` to retrieve active findings.
   - Filter for findings with severity `CRITICAL` or `HIGH`.
   - If no High/Critical issues are found, notify the user that no urgent remediation is required.

2. **Generate Fixes (Strict Security Guardrails)**:
   - **SQL Injection (CWE-89)**: Convert string interpolations (`f"SELECT ... {var}"`) to parameterized queries (`cursor.execute("SELECT ... WHERE id = %s", (var,))` or ORM bound parameters).
   - **Command Injection (CWE-78)**: Replace `shell=True` and string command concatenation with discrete argument lists (`subprocess.run(["cmd", arg1, arg2], shell=False)`) and apply `shlex.quote` where necessary.
   - **Path Traversal (CWE-22)**: Resolve absolute canonical paths with `os.path.realpath` / `Path.resolve()` and verify the target path stays within the base directory (`os.path.commonpath([base_dir, target_path]) == base_dir`).
   - **XSS (CWE-79)**: Contextually escape output using HTML sanitizers (e.g. `markupsafe.escape`, `DOMPurify.sanitize`).
   - **Hardcoded Secrets (CWE-798)**: Replace hardcoded strings with environment lookups (`os.getenv("SECRET_NAME")`) and redact the actual credentials (showing only `AKIA...XYZ`).
   - **BOLA / IDOR (CWE-639)**: Add mandatory ownership and tenant constraints (e.g. `WHERE id = :id AND user_id = :current_user_id`).

3. **Verify Every Patch Before Finalizing**:
   - For each proposed change, invoke the `secskill_verify_patch` MCP tool:
     - Pass the target file path and the candidate patch content.
     - Confirm that the vulnerability is eliminated and no new flaws or syntax regressions were introduced.

4. **Apply Verified Changes & Present Carousel**:
   - Use `edit_file` to write the verified fix into the target file.
   - Present the before and after code changes using Antigravity's ````carousel syntax:
     ````carousel
     ```python
     # [BEFORE] Vulnerable Code
     ...
     ```
     <!-- slide -->
     ```python
     # [AFTER] Verified Hardened Patch (secskill_verify_patch: PASS)
     ...
     ```
     ````
   - Provide verification summary confirming the vulnerability has been closed.
