# CI/CD Integration

Integrate SecSkill in GitHub Actions:

```yaml
- name: Run SecSkill
  run: |
    pip install secskill
    secskill scan . --format sarif --output secskill.sarif
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: secskill.sarif
```
