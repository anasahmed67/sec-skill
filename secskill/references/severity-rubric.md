# Severity Assessment Rubric (CVSS-Style Estimation)

> [!IMPORTANT]
> **Advisory Notice:** Severities assigned by SecSkill are **estimates for prioritization**, not official Common Vulnerability Scoring System (CVSS v3.1 / v4.0) ratings. A certified application security professional should validate ratings before formal reporting in compliance or production audits.

---

## 1. Evaluation Dimensions

SecSkill estimates finding severity using six fundamental metrics modeled after CVSS v3.1 Base Metrics:

| Metric | Factor | High Severity Indicator | Lower Severity Indicator |
|---|---|---|---|
| **AV** | Attack Vector | **Network (N):** Remotely exploitable without physical or local access. | **Local (L) / Physical (P):** Requires physical presence, shell access, or local console. |
| **AC** | Attack Complexity | **Low (L):** Repeatable exploit with standard payloads and no race conditions. | **High (H):** Dependent on specialized timing, race conditions, or rare environmental prerequisites. |
| **PR** | Privileges Required | **None (N):** Exploitable by unauthenticated, anonymous internet traffic. | **Low (L) / High (H):** Exploitation requires valid user login or administrative privileges. |
| **UI** | User Interaction | **None (N):** Headless execution (backend server flaw). | **Required (R):** Requires a victim to click a link or load a specific page (reflected XSS, CSRF). |
| **S** | Scope | **Changed (C):** Flaw compromises resources beyond the initial execution context (e.g., SSRF into cloud metadata, container escape). | **Unchanged (U):** Flaw impact is confined to the immediate vulnerable component. |
| **CIA** | Impact (Conf/Integ/Avail) | **High (H):** Total confidentiality loss, database overwrite, or service destruction. | **Low (L) / None (N):** Minor information disclosure, temporary disruption. |

---

## 2. Severity Bands & Decision Thresholds

| Severity | Typical CVSS Range | Definition & Criteria | Example Scenarios |
|:---:|:---:|---|---|
| **CRITICAL** | **9.0 – 10.0** | Remotely exploitable with **no authentication** (`PR:N`), **no user interaction** (`UI:N`), and **high impact** to confidentiality, integrity, or availability. | Unauthenticated RCE, unauthenticated SQL injection dumping customer data, exposed live root cloud keys (`AKIA...`), unauthenticated SSRF into AWS metadata. |
| **HIGH** | **7.0 – 8.9** | Significant impact requiring **limited prerequisites** (e.g., standard authenticated user `PR:L`, or user interaction `UI:R`), or local privilege escalation. | Stored XSS, authenticated SQL injection, IDOR allowing horizontal data leakage, unauthenticated path traversal reading configuration files. |
| **MEDIUM** | **4.0 – 6.9** | Exploitation requires **specific conditions**, complex interaction, or delivers limited impact (partial information disclosure, temporary denial of service). | Reflected XSS requiring social engineering, CSRF on non-critical actions, SSRF without internal access, weak PRNG used for non-financial tokens, missing rate limiting. |
| **LOW** | **0.1 – 3.9** | Minimal direct impact; theoretical risk; requires extensive privileged access or improbable execution paths. | Verbose stack traces in non-production environments, missing security headers (`X-Content-Type-Options`), outdated non-vulnerable libraries. |
| **INFORMATIONAL** | **0.0** | Best practice recommendation, defense-in-depth hardening, or code hygiene improvement. Not an exploitable vulnerability in its current state. | Absence of strict typing, code comments containing TODOs, opportunities to enable HSTS preload. |

---

## 3. Mandatory Downgrade Rules

SecSkill enforces strict rules to prevent severity inflation and avoid overwhelming engineering teams with false alarms:

1. **Privilege Requirement Downgrade:**
   - If a vulnerability (e.g., Command Injection or SQL Injection) is situated inside an admin-only endpoint (`@require_admin`, `is_superuser=True`), the finding MUST be downgraded by at least one band (e.g., **Critical -> High**).
   - *Report Note:* *"Requires authenticated administrative privileges (`PR:H`). Severity downgraded to High. Maintain input validation and parameterized calls for defense in depth."*

2. **Non-Routable / Local Scope Downgrade:**
   - If an insecure call exists in an offline build script, migration file, or internal CLI utility never exposed over HTTP, downgrade to **Medium** or **Low**.
   - *Report Note:* *"Triggered only via local CLI invocation (`AV:L`). Exploitability limited to local execution context."*

3. **Partial Mitigation / Filter Present:**
   - If partial input sanitization or regex validation exists that hinders trivial exploitation, downgrade to **Suspicious** with a requirement for dynamic verification.

