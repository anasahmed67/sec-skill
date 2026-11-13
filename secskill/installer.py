"""
secskill/installer.py
Omni-Agent Installation Engine for Antigravity, Claude Code, Cursor, and Codex.
Enables SecSkill to be installed as an autonomous skill, MCP server, or rule set in any AI coding agent.
"""
from pathlib import Path
from typing import Dict, List

SKILL_MD_CONTENT = """---
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
"""

CURSOR_MDC_CONTENT = """---
description: SecSkill Security Reviewer & Vulnerability Guardrail
globs: **/*.{py,js,ts,jsx,tsx,java,go,rs,rb,php,cs,c,cpp,yml,yaml,json}
alwaysApply: false
---

# SecSkill Security Guardrails for Cursor

When developing, refactoring, or reviewing code:
1. **Prevent Injections (CWE-89, CWE-78):**
   - NEVER concatenate strings or f-strings into SQL queries or shell executions.
   - Always use driver parameterization (e.g. `cursor.execute("SELECT ... WHERE id = ?", (user_id,))`).
   - Use `subprocess.run(["cmd", arg1], shell=False)` instead of `shell=True`.
2. **Prevent Broken Object-Level Authorization (BOLA/IDOR - CWE-639, CWE-862):**
   - In multi-tenant systems, ALWAYS verify ownership in database queries: `WHERE id = :id AND tenant_id = :current_tenant`.
3. **Secrets & Cryptography (CWE-798, CWE-327):**
   - Never hardcode API keys, JWT secrets, passwords, or tokens.
   - Use `secrets` (CSPRNG) for tokens; use Argon2id or bcrypt for password hashing (no MD5/SHA1).
4. **Web Security & Headers (OWASP A05):**
   - Ensure cookies specify `HttpOnly`, `Secure`, and `SameSite=Lax/Strict`.
   - Never set `Access-Control-Allow-Origin: *` when `Access-Control-Allow-Credentials: true`.
5. **Pre-commit Verification:**
   - Run `secskill scan --diff main` or `secskill scan <file>` before committing.
"""

CLAUDE_RULES_CONTENT = """# SecSkill Claude Code Security Rules

You have the SecSkill security reviewer active. Follow these hard constraints:
1. **Defensive Rigor:** Check all code you generate against OWASP Top 10 and CWE Top 25.
2. **Parameterize Everything:** No SQL string interpolation; no `shell=True` in subprocesses; no `pickle.loads` or unsafe `yaml.load`.
3. **Secrets:** Redact detected tokens immediately. Never output raw keys.
4. **Verified Remediation:** When fixing a security vulnerability, run `secskill scan <file>` to verify zero remaining findings.
"""

ANTIGRAVITY_PLUGIN_JSON = """{
  "name": "secskill",
  "version": "0.2.0",
  "displayName": "SecSkill Security Reviewer",
  "description": "Agent-native security analysis engine for source code, websites, and AI-agent architectures.",
  "author": "SecSkill Maintainers",
  "skills": [
    {
      "name": "secskill",
      "path": "skills/secskill/SKILL.md"
    }
  ],
  "mcpServers": {
    "secskill": {
      "command": "secskill",
      "args": ["mcp"]
    }
  }
}
"""

CURSOR_MCP_JSON = """{
  "mcpServers": {
    "secskill": {
      "command": "secskill",
      "args": ["mcp"]
    }
  }
}
"""

GENERIC_MCP_CONFIG = """{
  "mcpServers": {
    "secskill": {
      "command": "secskill",
      "args": ["mcp"],
      "description": "SecSkill SAST/DAST Security Reviewer for AI Agents"
    }
  }
}
"""

GITHUB_WORKFLOW = """name: SecSkill Security Scan

on:
  pull_request:
    branches: [main, master]
  push:
    branches: [main, master]

jobs:
  secskill:
    name: SecSkill SAST & SCA Scan
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install SecSkill
        run: pip install secskill

      - name: Run SecSkill Scan
        run: secskill scan . --format sarif --output secskill.sarif

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: secskill.sarif
"""

class AgentInstaller:
    """Installs SecSkill skills, MCP configurations, and rules for AI coding assistants."""

    @staticmethod
    def install_antigravity(target_dir: Path) -> List[str]:
        created = []
        skills_dir = target_dir / ".gemini" / "skills" / "secskill"
        skills_dir.mkdir(parents=True, exist_ok=True)
        skill_file = skills_dir / "SKILL.md"
        skill_file.write_text(SKILL_MD_CONTENT, encoding="utf-8")
        created.append(str(skill_file))

        plugins_dir = target_dir / ".gemini" / "plugins" / "secskill"
        plugins_dir.mkdir(parents=True, exist_ok=True)
        plugin_file = plugins_dir / "plugin.json"
        plugin_file.write_text(ANTIGRAVITY_PLUGIN_JSON, encoding="utf-8")
        created.append(str(plugin_file))
        return created

    @staticmethod
    def install_claude(target_dir: Path) -> List[str]:
        created = []
        claude_skills_dir = target_dir / ".claude" / "skills" / "secskill"
        claude_skills_dir.mkdir(parents=True, exist_ok=True)
        skill_file = claude_skills_dir / "SKILL.md"
        skill_file.write_text(SKILL_MD_CONTENT, encoding="utf-8")
        created.append(str(skill_file))

        rules_file = target_dir / ".claude" / "rules.md"
        rules_file.write_text(CLAUDE_RULES_CONTENT, encoding="utf-8")
        created.append(str(rules_file))

        claude_md = target_dir / "CLAUDE.md"
        if not claude_md.exists():
            claude_md.write_text(CLAUDE_RULES_CONTENT, encoding="utf-8")
            created.append(str(claude_md))
        return created

    @staticmethod
    def install_cursor(target_dir: Path) -> List[str]:
        created = []
        rules_dir = target_dir / ".cursor" / "rules"
        rules_dir.mkdir(parents=True, exist_ok=True)
        mdc_file = rules_dir / "secskill.mdc"
        mdc_file.write_text(CURSOR_MDC_CONTENT, encoding="utf-8")
        created.append(str(mdc_file))

        mcp_file = target_dir / ".cursor" / "mcp.json"
        mcp_file.write_text(CURSOR_MCP_JSON, encoding="utf-8")
        created.append(str(mcp_file))

        cursorrules = target_dir / ".cursorrules"
        cursorrules.write_text(CURSOR_MDC_CONTENT, encoding="utf-8")
        created.append(str(cursorrules))
        return created

    @staticmethod
    def install_codex(target_dir: Path) -> List[str]:
        created = []
        mcp_dir = target_dir / ".mcp"
        mcp_dir.mkdir(parents=True, exist_ok=True)
        mcp_file = mcp_dir / "secskill.json"
        mcp_file.write_text(GENERIC_MCP_CONFIG, encoding="utf-8")
        created.append(str(mcp_file))

        agent_md = target_dir / "AGENTS.md"
        if not agent_md.exists():
            agent_md.write_text(SKILL_MD_CONTENT, encoding="utf-8")
            created.append(str(agent_md))
        return created

    @staticmethod
    def install_ci(target_dir: Path) -> List[str]:
        created = []
        workflows_dir = target_dir / ".github" / "workflows"
        workflows_dir.mkdir(parents=True, exist_ok=True)
        workflow_file = workflows_dir / "secskill.yml"
        workflow_file.write_text(GITHUB_WORKFLOW, encoding="utf-8")
        created.append(str(workflow_file))
        return created

    @classmethod
    def install_all(cls, target_dir: Path) -> Dict[str, List[str]]:
        results = {
            "antigravity": cls.install_antigravity(target_dir),
            "claude": cls.install_claude(target_dir),
            "cursor": cls.install_cursor(target_dir),
            "codex": cls.install_codex(target_dir),
            "ci": cls.install_ci(target_dir),
        }
        return results

