# SecSkill Report Formats & Schemas

SecSkill produces structured outputs in three primary formats: Markdown (default for developer and agent chat), JSON (for programmatic integration), and SARIF 2.1.0 (for GitHub Code Scanning and enterprise SAST dashboards).

---

## 1. Markdown Format Specification

The default Markdown report adheres to the seven-section structure:

```markdown
# SecSkill Security Review Report

**Scan Target:** `src/app`
**Execution Timestamp:** 2026-10-31T14:50:00Z
**Languages Detected:** Python (85%), JavaScript (15%)
**Engines Active:** Built-in Static Rules, Secret Scanner, Dependency Auditor
**Engines Skipped:** Semgrep (not installed in PATH), Bandit (not installed in PATH)

### Summary of Findings
| Severity | Confirmed | Likely | Suspicious | Informational | Total |
|---|:---:|:---:|:---:|:---:|:---:|
| **Critical** | 1 | 0 | 0 | 0 | 1 |
| **High**     | 1 | 1 | 0 | 0 | 2 |
| **Medium**   | 0 | 1 | 1 | 0 | 2 |
| **Low**      | 0 | 0 | 1 | 0 | 1 |
| **Info**     | 0 | 0 | 0 | 2 | 2 |
| **Total**    | 2 | 2 | 2 | 2 | 8 |

---

## 1. Top Risks (Critical & High)

### [F-1001] SQL Injection via String Formatting
- **Severity:** `CRITICAL` (Estimated CVSS: 9.8 - `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
- **Confidence:** 0.93 (Confirmed)
- **CWE:** CWE-89 (Improper Neutralization of Special Elements used in an SQL Command)
- **OWASP:** A03:2021-Injection
- **SSDF Practice:** PW.5.1
- **Location:** `app/users.py:42`
- **Requires Human Review:** No

#### Code Snippet
```python
41: def get_user_profile(user_id):
42:     query = f"SELECT * FROM users WHERE id = '{user_id}'"
43:     cursor.execute(query)
```

#### Attack Path & Evidence
Untrusted parameter `user_id` is passed from the HTTP request handler directly into an SQL string f-string on line 42 without type casting or parameter binding. An attacker can submit `' OR '1'='1` to dump table contents.

#### Recommended Remediation
Use parameterized queries with bound placeholders:
```python
- query = f"SELECT * FROM users WHERE id = '{user_id}'"
- cursor.execute(query)
+ cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```

#### Validation Steps
1. Execute unit test passing `' OR 1=1 --` and verify database returns 400 or no match.
2. Verify query parameters are bound separately in database logs.

---

## 2. Medium and Low Findings
| ID | Title | File & Line | Severity | Status | Fix Summary |
|---|---|---|:---:|:---:|---|
| F-1003 | Weak PRNG for Reset Token | `auth.py:88` | Medium | Likely | Replace `random.randint` with `secrets.token_urlsafe(32)`. |

---

## 3. Items Needing Human Review
- **[F-1004] Potential IDOR on Document Retrieval (`routes/docs.py:15`):** Record fetched by `doc_id` from request parameters. Verify whether `current_user.organization_id` is enforced in the query filter.

---

## 4. Hardening Suggestions (Informational)
- Enable Content Security Policy (CSP) headers in Express gateway.
- Add rate limiting middleware to `/api/v1/auth/login`.

---

## 5. Scan Limitations
- Dynamic runtime execution was not performed.
- External SAST tool `semgrep` was not available in PATH; analysis relied on built-in rules and LLM contextual triage.
- Third-party packages were audited via lockfile versions; private enterprise feeds were not queried.

---

## 6. Next Steps & Re-Scan
- Review proposed diffs for Critical findings: `secskill fix --finding F-1001 --dry-run`
- Re-run scan after remediation: `secskill scan --diff main`
```

---

## 2. JSON Format Specification

The unified JSON output schema matches:

```json
{
  "version": "1.0.0",
  "tool": "secskill",
  "target": ".",
  "summary": {
    "total_findings": 1,
    "by_severity": { "critical": 1, "high": 0, "medium": 0, "low": 0, "informational": 0 },
    "by_decision": { "confirmed": 1, "likely": 0, "suspicious": 0, "false_positive": 0, "informational": 0 }
  },
  "findings": [
    {
      "finding_id": "F-1042",
      "title": "SQL Injection via String Formatting",
      "cwe": "CWE-89",
      "owasp": "A03:2021-Injection",
      "ssdf": "PW.5.1",
      "severity": "critical",
      "confidence": 0.93,
      "decision": "confirmed",
      "file": "app/users.py",
      "line": 42,
      "end_line": 43,
      "source": "static_analysis",
      "tool": "builtin_rules",
      "evidence": "User-controlled input reaches cursor.execute() without parameterization",
      "attack_path": "HTTP parameter user_id reaches SQL query without parameterization",
      "exploitability": "high",
      "recommended_fix": "Use parameterized query with bound parameters",
      "validation_steps": [
        "Submit user_id=1 OR 1=1 to test endpoint",
        "Verify query uses bound parameters in database logs",
        "Add regression test for malicious input"
      ],
      "requires_human_review": false,
      "status": "confirmed"
    }
  ]
}
```

---

## 3. SARIF 2.1.0 Specification

SARIF (Static Analysis Results Interchange Format) integrates directly with GitHub Code Scanning:

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "SecSkill",
          "version": "0.1.0",
          "informationUri": "https://github.com/secskill/secskill",
          "rules": [
            {
              "id": "SEC-089-SQLI",
              "name": "SqlInjection",
              "shortDescription": { "text": "SQL Injection via String Formatting" },
              "fullDescription": { "text": "User input formatted directly into SQL query strings." },
              "defaultConfiguration": { "level": "error" },
              "help": {
                "text": "Use parameterized queries with bound placeholders.",
                "markdown": "### Remediation\nUse parameterized queries.\n```python\ncursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))\n```"
              },
              "properties": {
                "tags": ["security", "CWE-89", "A03:2021-Injection"],
                "precision": "high"
              }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "SEC-089-SQLI",
          "level": "error",
          "message": { "text": "SQL Injection vulnerability detected in cursor.execute()" },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "app/users.py" },
                "region": { "startLine": 42, "endLine": 43 }
              }
            }
          ]
        }
      ]
    }
  ]
}
```

