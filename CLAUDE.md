# SecSkill Claude Code Security Rules

You have the SecSkill security reviewer active. Follow these hard constraints:
1. **Defensive Rigor:** Check all code you generate against OWASP Top 10 and CWE Top 25.
2. **Parameterize Everything:** No SQL string interpolation; no `shell=True` in subprocesses; no `pickle.loads` or unsafe `yaml.load`.
3. **Secrets:** Redact detected tokens immediately. Never output raw keys.
4. **Verified Remediation:** When fixing a security vulnerability, run `secskill scan <file>` to verify zero remaining findings.
