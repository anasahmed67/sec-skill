---
name: secscan
description: "Runs full static analysis across the repository and exports a SARIF report. Also triggered by the /secscan slash command."
metadata:
  icon: security
---

# /secscan: Full Repository Static Security Analysis & SARIF Export

Executes deep Static Application Security Testing (SAST), AST data flow taint tracking, hardcoded secret detection, and dependency auditing across the workspace, exporting the results to SARIF 2.1.0 for GitHub Code Scanning and IDE display.

## Execution Procedure

1. **Target Identification**:
   - Determine repository root (default: current working directory `.`).
   - If user specified a subpath or directory, use that target.

2. **Run Static Analysis & Export SARIF**:
   - Execute the scan using the `secskill_scan` MCP tool with `path="."` (or target path), or run via CLI:
     `secskill scan . --sarif secskill-report.sarif`
   - If an HTML report is also useful, execute:
     `secskill scan . --sarif secskill-report.sarif --report secskill-report.html`

3. **Analyze and Tally Findings**:
   - Categorize all findings by severity:
     - 🔴 **CRITICAL**: Remote Code Execution (CWE-78/94), Unauthenticated SQL Injection (CWE-89), Exposed Cloud Keys/Private Keys.
     - 🟠 **HIGH**: Stored/Reflected XSS (CWE-79), SSRF (CWE-918), BOLA / IDOR (CWE-639/862), Insecure Deserialization (CWE-502).
     - 🟡 **MEDIUM**: Weak crypto/hashing algorithms (MD5/SHA1 for auth), Missing CSRF protection, Insecure cookie flags.
     - 🔵 **LOW / INFO**: Verbose error messages, missing hardening headers.

4. **Visual Native Attack Path (Mermaid)**:
   - For all Critical and High findings, generate a Mermaid flowchart (`flowchart LR`) illustrating the taint dataflow:
     - Untrusted input source (`req.body`, `params`)
     - Route/dispatcher component
     - Vulnerable sink (`cursor.execute`, `subprocess.run`, `open()`, template render)
     - Impact (RCE, Data Exfiltration, Privilege Escalation)

5. **Generative UI & Visual Dashboard**:
   - Save the interactive Antigravity Generative UI dashboard (`secskill_dashboard.html`) into the conversation artifact directory using `write_file` with `ArtifactMetadata` (`UserFacing: true`).
   - Embed the interactive dashboard widget directly into the response using:
     `<agent-embed src="file:///<artifact_dir>/secskill_dashboard.html"></agent-embed>`

6. **Output Report**:
   - Present an executive summary table:
     - Total files scanned
     - Severity counts (Critical, High, Medium, Low)
     - Top vulnerable files and CWE IDs
   - Confirm generated SARIF file path: `[secskill-report.sarif](file:///secskill-report.sarif)`.
   - If Critical or High findings exist, suggest running `/secpatch` to auto-remediate and verify fixes.
