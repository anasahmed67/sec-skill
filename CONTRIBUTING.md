# Contributing to SecSkill

Thank you for your interest in contributing to SecSkill! SecSkill is an open-source, Apache 2.0-licensed agent skill and security analysis engine dedicated to making AI-generated and human-written code safer.

---

## 1. Development Setup

SecSkill requires Python 3.10+ and standard build tools.

```bash
# 1. Clone your fork of the repository
git clone https://github.com/<your-username>/secskill.git
cd secskill

# 2. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# 3. Install SecSkill in editable mode with development dependencies
pip install -e ".[dev,all]"

# 4. Install pre-commit hooks
pre-commit install
```

---

## 2. Coding & Quality Standards

- **Code Formatting & Linting:** We use `ruff` for linting and code formatting:
  ```bash
  ruff check .
  ruff format .
  ```
- **Type Checking:** All Python code must include type annotations:
  ```bash
  mypy secskill
  ```
- **Testing:** All pull requests must maintain 100% passing tests:
  ```bash
  pytest tests/
  ```

---

## 3. Contributing New Security Rules

We welcome community rules for Python, JavaScript, TypeScript, Java, and emerging language packs!

1. Rules are located in `secskill/rules/<category>.yaml`.
2. Review [secskill/references/rule-authoring.md](file:///secskill/references/rule-authoring.md) for the exact YAML schema.
3. Every rule must include:
   - Unique Rule ID: `SEC-<CWE>-<SLUG>`
   - MITRE CWE and OWASP Top 10 (2021) mapping
   - Estimated default severity
   - Detection regex or AST patterns
   - Taint dataflow sources and sinks
   - Remediation text with before-and-after code blocks
   - Both a vulnerable test fixture and a secure negative fixture

---

## 4. Contributing Benchmark Samples

To validate real-world detection accuracy:
- Add vulnerable samples to `benchmarks/vulnerable_samples/`
- Add secure control samples to `benchmarks/secure_samples/`
- Add AI failure mode samples to `benchmarks/ai_generated_samples/`
- Update `benchmarks/ground_truth.json` with expected findings and CWE mappings.

---

## 5. Pull Request Guidelines

1. Create a descriptive feature branch (`git checkout -b feature/add-ssrf-rule`).
2. Run test suites locally before submitting:
   ```bash
   pytest
   python secskill/scripts/index_repo.py .
   ```
3. Commit messages should be concise and explain the rationale.
4. When opening a Pull Request, describe:
   - The security vulnerability or weakness addressed.
   - The threat model impact and OWASP/CWE references.
   - Any external tools required (if applicable).
