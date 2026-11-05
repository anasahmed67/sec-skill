# SecSkill Security Review Report

**Scan Target:** `{{ target }}`  
**Scan Timestamp:** {{ timestamp }}  
**Languages Detected:** {{ languages_summary }}  
**Engines Active:** {{ tools_executed }}  
**Engines Skipped:** {{ tools_skipped }}  

---

### Executive Summary

| Severity | Confirmed | Likely | Suspicious | Informational | Total |
|---|:---:|:---:|:---:|:---:|:---:|
| **Critical** | {{ counts.critical_confirmed }} | {{ counts.critical_likely }} | {{ counts.critical_suspicious }} | 0 | {{ counts.critical_total }} |
| **High**     | {{ counts.high_confirmed }} | {{ counts.high_likely }} | {{ counts.high_suspicious }} | 0 | {{ counts.high_total }} |
| **Medium**   | {{ counts.medium_confirmed }} | {{ counts.medium_likely }} | {{ counts.medium_suspicious }} | 0 | {{ counts.medium_total }} |
| **Low**      | {{ counts.low_confirmed }} | {{ counts.low_likely }} | {{ counts.low_suspicious }} | 0 | {{ counts.low_total }} |
| **Info**     | 0 | 0 | 0 | {{ counts.info_total }} | {{ counts.info_total }} |
| **Total**    | {{ counts.total_confirmed }} | {{ counts.total_likely }} | {{ counts.total_suspicious }} | {{ counts.info_total }} | **{{ counts.grand_total }}** |

---

## 1. Top Risks (Critical & High)

{% for finding in top_risks %}
### [{{ finding.finding_id }}] {{ finding.title }}

- **Severity:** `{{ finding.severity | upper }}` (Estimated CVSS: {{ finding.cvss_vector | default("N/A") }})
- **Confidence:** {{ finding.confidence }} ({{ finding.decision | capitalize }})
- **CWE:** {{ finding.cwe }}
- **OWASP Category:** {{ finding.owasp }}
- **SSDF Practice:** {{ finding.ssdf | default("PW.5.1") }}
- **Location:** `{{ finding.file }}:{{ finding.line }}`
- **Requires Human Review:** {{ "Yes" if finding.requires_human_review else "No" }}

#### Vulnerable Code Snippet
```
{{ finding.snippet }}
```

#### Attack Path & Evidence
{{ finding.attack_path }}
*Evidence:* {{ finding.evidence }}

#### Recommended Remediation
{{ finding.recommended_fix }}

```diff
{{ finding.diff_preview }}
```

#### Verification Steps
{% for step in finding.validation_steps %}
- [ ] {{ step }}
{% endfor %}

---
{% endfor %}

## 2. Medium and Low Findings

| ID | Title | File & Line | Severity | Status | Fix Summary |
|---|---|---|:---:|:---:|---|
{% for finding in medium_low_risks %}
| {{ finding.finding_id }} | {{ finding.title }} | `{{ finding.file }}:{{ finding.line }}` | {{ finding.severity | capitalize }} | {{ finding.decision | capitalize }} | {{ finding.recommended_fix | truncate(60) }} |
{% endfor %}

---

## 3. Items Needing Human Review

The following items are context-dependent and cannot be conclusively verified without human engineering context:

{% for item in human_review_items %}
- **[{{ item.finding_id }}] {{ item.title }} (`{{ item.file }}:{{ item.line }}`):**  
  *Context:* {{ item.evidence }}  
  *What settles this:* {{ item.settlement_criteria }}
{% endfor %}

---

## 4. Hardening Suggestions (Informational)

{% for info in informational_items %}
- **{{ info.title }} (`{{ info.file }}`):** {{ info.evidence }}  
  *Recommendation:* {{ info.recommended_fix }}
{% endfor %}

---

## 5. Limitations of This Scan

- **Scope:** Dynamic runtime analysis, fuzzer coverage, and binary reverse-engineering were not performed.
- **External Tools:** {{ tools_skipped_notice }}
- **Environment Context:** Cloud IAM roles, live database access controls, and container network policies were not inspected.
- **AI-Generated Weaknesses:** Business logic nuances and multi-tenant domain boundaries require human architectural validation.

---

## 6. Suggested Next Steps

1. Review and approve diffs for Critical and High findings:
   ```bash
   secskill fix --finding <FINDING_ID> --dry-run
   ```
2. Re-scan modified files to verify resolution:
   ```bash
   secskill scan --diff main
   ```
3. Export SARIF for GitHub Code Scanning:
   ```bash
   secskill scan --format sarif --output secskill.sarif
   ```

