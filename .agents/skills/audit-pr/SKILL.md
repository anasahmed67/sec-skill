---
name: audit-pr
description: "Compares the current git branch against main, auditing only the modified files for regressions or new CVEs. Also triggered by the /audit-pr slash command."
metadata:
  icon: rate_review
---

# /audit-pr: Differential Branch & Pull Request Security Review

Audits only modified files, diffs, and dependencies in the current branch against the target branch (default `main`), ensuring newly committed code introduces zero security regressions, hardcoded secrets, or CVEs.

## Execution Procedure

1. **Inspect Git Diff & Changed Files**:
   - Run `git rev-parse --abbrev-ref HEAD` to check current branch.
   - Identify changed files against `main`:
     `git diff --name-only main...HEAD` (or `origin/main...HEAD`, falling back to `git status --porcelain` if on main or if working with unstaged files).
   - Filter for source files, configuration files, and package manifests.

2. **Targeted Differential Security Scan**:
   - For each modified source file, run `secskill_scan` on that file, or execute:
     `secskill scan --diff main`
   - If manifest/lockfiles changed (`requirements.txt`, `package.json`, `poetry.lock`, `Cargo.toml`), perform dependency vulnerability checking (`secskill scan --deps`).

3. **Diff Analysis & Secret Leak Check**:
   - Scan diff chunks for newly added credentials, high-entropy tokens, private keys, or debug flags (`DEBUG = True`, `disable_web_security`).
   - Verify that new API endpoints include authentication decorators, RBAC checks, and tenant isolation.

4. **PR Verdict & Review Summary**:
   - Output structured PR Review Card:
     - **Merge Recommendation**:
       - 🟢 **APPROVE**: Zero Critical/High issues found.
       - 🟡 **COMMENT**: Only Medium/Low style or informational security suggestions.
       - 🔴 **CHANGES REQUESTED**: Block merge due to detected Critical/High flaw or exposed credential.
     - **Changed Files Audited**: list of files inspected.
     - **Detailed Findings**: File, line number, flaw description, and concrete remediation.

