# NIST SP 800-218 SSDF Practice Mapping

The NIST Secure Software Development Framework (SSDF) defines core recommendations for integrating security across the software lifecycle. SecSkill aligns findings and remediation guidance with the four SSDF practice groups:

- **PO:** Prepare the Organization
- **PS:** Protect Software
- **PW:** Produce Well-Secured Software
- **RV:** Respond to Vulnerabilities

---

## SSDF Practice Groups & SecSkill Alignment

| SSDF Practice | Description | Applicable SecSkill Findings | Remediation Guidance Alignment |
|---|---|---|---|
| **PW.1.1** | Design software to meet security requirements and mitigate security risks. | Architectural gaps, missing rate limiters, weak session models (CWE-284, CWE-400). | Redesign endpoint authentication gates, implement token expiration, apply defense-in-depth design. |
| **PW.5.1** | Create source code adhering to secure coding practices to prevent vulnerabilities. | Injection (CWE-89, CWE-78, CWE-94), XSS (CWE-79), Path Traversal (CWE-22), XXE (CWE-611). | Adopt parameterized SQL queries, use argument lists with `shell=False`, implement context-aware escaping. |
| **PW.6.1** | Configure software build and deployment processes to harden binaries and configurations. | Debug flags enabled in production, permissive CORS, cleartext communications (CWE-489, CWE-942, CWE-319). | Disable debug modes, enforce HTTPS, configure restrictive CORS headers, secure environment variables. |
| **PW.7.1** | Review and inspect human-written and AI-generated source code to identify vulnerabilities. | All static AST, regex, and LLM contextual findings. | Code reviews, continuous automated pre-commit scanning, and pull request gating. |
| **PW.8.1** | Test executable code for security vulnerabilities. | High/Critical findings requiring dynamic verification. | Generate automated unit regression tests with benign test vectors. |
| **PS.1.1** | Protect all forms of code from unauthorized access and tampering. | Insecure repository file permissions, exposed deployment scripts, tampering risks. | Enforce branch protection rules, require signed commits, restrict write permissions. |
| **PS.2.1** | Safeguard software release integrity and supply chain dependencies. | Insecure direct package downloads, unpinned packages, lack of integrity checksums (CWE-494, CWE-829). | Pin package versions in lockfiles (`package-lock.json`, `poetry.lock`), verify package hashes. |
| **PO.1.2** | Define and maintain policies for secure development across tools and agents. | Insecure AI-agent tool configurations, prompt injection sinks (CWE-74). | Establish agent boundary policies, system prompt isolation, and least-privilege tool execution. |
| **RV.1.1** | Identify and confirm vulnerabilities in released software and third-party components. | Vulnerable third-party dependencies (OWASP A06, CVE-linked packages). | Monitor dependency advisories via OSV/NVD, automate dependency update alerts (Dependabot, Renovate). |
| **RV.2.1** | Rapidly remediate vulnerabilities and deploy security updates. | All confirmed findings with actionable patches. | Prioritize Critical/High patches, apply automated minimal diffs, verify regression testing. |
| **RV.3.1** | Analyze vulnerabilities to prevent recurrence in future code generation. | Repeated AI generation anti-patterns. | Update custom YAML rules (`secskill/rules/`), refine agent prompt instructions. |

---

## Embedding SSDF in SecSkill Reports

When reporting findings, include the specific SSDF practice ID in the finding metadata block:
```json
{
  "finding_id": "F-1001",
  "title": "SQL Injection via String Formatting",
  "cwe": "CWE-89",
  "owasp": "A03:2021-Injection",
  "ssdf": "PW.5.1",
  "severity": "critical"
}
```
This enables enterprise compliance reporting, audit tracking, and executive assurance.

