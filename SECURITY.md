# Security Policy & Responsible Disclosure

SecSkill takes the security of its code and the security posture of our users seriously. We appreciate the responsible disclosure of any vulnerability discovered in our software, agent skills, scripts, or benchmark datasets.

---

## 1. Supported Versions

We actively provide security updates and patches for the following versions:

| Version | Supported | Status |
|---|:---:|---|
| `0.1.x` (current) | Yes | Actively maintained |
| `< 0.1.0` | No | Deprecated |

---

## 2. Reporting a Vulnerability

If you discover a security vulnerability or weakness in SecSkill:

1. **Do NOT report security vulnerabilities via public GitHub issues, discussions, or pull requests.**
2. Report via **GitHub Private Vulnerability Reporting** directly on the repository:
   - Navigate to the **Security** tab of the repository on GitHub.
   - Click **Report a vulnerability** to open an advisory draft.
3. Alternatively, send an encrypted GPG email to:
   - **`security@secskill.dev`**
   - Please include:
     - Target component (CLI, analyzer, script, rule, or agent prompt).
     - Step-by-step reproduction instructions or a minimal, non-weaponized test case.
     - Potential threat impact and estimated CVSS severity.

---

## 3. Response SLAs and Disclosure Process

- **Acknowledgment:** Within **48 hours** of receiving your report.
- **Triage & Reproduction:** Within **5 business days**, our security team will confirm or clarify the report.
- **Fix & Verification:** Critical and High severity issues will receive a patch within **14 business days**.
- **Coordinated Disclosure:** We coordinate public release and CVE assignment with a standard **90-day** disclosure window, unless mutually agreed otherwise.

---

## 4. Safe Harbor for Security Researchers

Activities conducted in good faith under this policy are considered authorized. SecSkill will not initiate legal action against researchers who:
- Perform testing only within authorized scopes and avoid disrupting services.
- Never access, download, or compromise third-party user data.
- Do not exploit a security issue beyond the minimum required to prove its existence.
- Adhere to responsible disclosure timelines.

---

## 5. Compromised Secrets Guidance

If you accidentally commit real credentials, API tokens, or private keys to a repository:
1. **Rotate and Revoke:** Invalidate the exposed secret at the credential provider immediately.
2. **Scrub Git History:** Use tools like `git-filter-repo` or BFG Repo-Cleaner to rewrite history. Simply deleting the file in a new commit does not remove the secret from git history.
