---
name: secskill
description: "Use this skill whenever the user asks for a security review, audit, scan, or vulnerability check of code, a diff, a file, a pull request, a repository, or a live website/URL; asks whether AI-generated code is safe or secure; mentions SQL injection, XSS, command injection, path traversal, SSRF, insecure deserialization, hardcoded secrets, weak crypto, broken access control (BOLA/IDOR), vulnerable dependencies, TLS/SSL, security headers (CSP, HSTS), OWASP Top 10, CWE, CVSS, SARIF, or ISO 27001; or asks to review a PR before merge. Do NOT trigger for general style, performance, or unauthorized penetration testing."
---

# SecSkill: Omni-Agent Security Reviewer & Framework Auditor

SecSkill is an agent-native application and website security reviewer. It audits codebases, pull requests, single files, and live websites against international standards: **OWASP Top 10 (2021)**, **OWASP API Top 10 (2023)**, **OWASP LLM Top 10 (2025)**, **CWE Top 25**, **NIST SP 800-218 (SSDF)**, **NIST SP 800-53**, and **ISO/IEC 27001 (Annex A.8)**.

## Core Capabilities
1. **Source Code SAST & Taint Analysis:** `secskill scan <path>`
2. **Live Website & DAST Audit:** `secskill scan-url <url>` (Audits TLS/SSL, CSP, HSTS, XFO, CORS, cookies, sensitive exposures)
3. **Automated Remediation Verification:** `secskill_verify_patch` tool (confirms if proposed fixes eliminate vulnerabilities without regressions)
4. **AI Agent & MCP Defense:** `secskill audit-agent <path>` (Audits prompts, tools, and MCP servers for prompt injection and excessive privileges)
5. **Real-time Secret Leaks Protection:** `secskill watch <path>`

## Agent Review Workflow
1. When generating or modifying code, evaluate against SecSkill rules before finalizing changes.
2. If `CRITICAL` or `HIGH` vulnerabilities are found, remediate immediately using parameterized queries, safe subprocess lists (`shell=False`), and environment secrets.
3. Use the `secskill_verify_patch` tool to verify your fix before presenting it to the user.
4. Redact all detected credentials (first 4, last 3 characters: `AKIA...XYZ`).
