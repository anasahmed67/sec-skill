"""Analyzer for Agent Skill and Rule definitions (SKILL.md, AGENT.md, .cursorrules)."""
import re
from pathlib import Path
from typing import List
from secskill.models import Severity
from secskill.agent_audit.models import (
    AgentFinding,
    AgentFindingCategory,
)

DANGEROUS_DIRECTIVE_PATTERNS = [
    (r"\bignore\s+(?:all\s+)?(?:security|safety)\s+(?:warnings?|checks?|rules?)\b", "Instruction to Ignore Security Warnings"),
    (r"\b(?:disable|turn\s+off|bypass)\s+(?:security|safety|guardrails?|confirmation|checks?)\b", "Instruction to Bypass Security or Confirmation"),
    (r"\balways\s+(?:run|execute)\s+with\s+shell\s*=\s*True\b", "Directive Enforcing shell=True"),
    (r"\bexecute\s+(?:any|all)\s+commands?\s+without\s+(?:confirmation|asking|prompting)\b", "Unattended Command Execution Directive"),
    (r"\btrust\s+all\s+(?:user\s+)?input\b", "Instruction to Blindly Trust Input"),
]

BACKGROUND_DAEMON_PATTERNS = [
    (r"\blaunch\s+(?:hidden|stealth|untracked)\s+(?:background|daemon)\s+process\b", "Stealth Background Process Directive"),
    (r"\bspawn\s+(?:reverse\s+shell|persistent\s+listener)\b", "Reverse Shell / Persistent Listener Directive"),
]

class AgentSkillAnalyzer:
    """Audits agent skill instruction documents, Cursor rules, and AGENT.md files."""

    def is_skill_file(self, file_path: Path) -> bool:
        """Identify agent skill and rule configuration documents."""
        fname = file_path.name.lower()
        if fname in {
            "skill.md", "agent.md", "claude.md", ".cursorrules",
            ".windsurfrules", ".copilot-instructions.md"
        }:
            return True
        if "skill" in fname and fname.endswith(".md"):
            return True
        if file_path.parent.name.lower() in {"skills", ".gemini", ".claude", ".cursor"}:
            return True
        return False

    def analyze_file(self, file_path: Path) -> List[AgentFinding]:
        findings: List[AgentFinding] = []
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return findings

        rel_path = str(file_path).replace("\\", "/")
        lines = content.splitlines()

        # 1. Hardcoded API secrets in skill markdown
        for idx, line in enumerate(lines, start=1):
            if re.search(r"sk-(?:proj-)?[A-Za-z0-9_-]{24,}", line) or re.search(r"ghp_[A-Za-z0-9_]{30,}", line):
                masked = line.strip()[:60] + "..."
                findings.append(AgentFinding(
                    id=f"AGENT-SKL-{len(findings) + 1:03d}",
                    rule_id="AGENT-SKILL-002",
                    category=AgentFindingCategory.AGENT_SKILL,
                    title="Hardcoded API Token / Secret Inside Agent Skill Document",
                    description=(
                        f"Agent skill file '{file_path.name}' contains a hardcoded API token. "
                        "When an LLM agent ingests this skill context, it can inadvertently expose the token in conversation transcripts or tool payloads."
                    ),
                    severity=Severity.HIGH,
                    file_path=rel_path,
                    line_number=idx,
                    code_snippet=masked,
                    owasp_llm="LLM02: Sensitive Information Disclosure",
                    mitre_atlas="AML.T0053: Exfiltration via Model Outputs",
                    cwe_id="CWE-798",
                    remediation="Remove the credential from the skill file and configure it via secure environment variables or vault.",
                    suggested_fix="# Reference environment variable instead of embedding token in skill doc",
                ))

        # 2. Dangerous override directives
        for idx, line in enumerate(lines, start=1):
            line_clean = line.strip().lower()
            for pattern, pattern_title in DANGEROUS_DIRECTIVE_PATTERNS:
                if re.search(pattern, line_clean):
                    findings.append(AgentFinding(
                        id=f"AGENT-SKL-{len(findings) + 1:03d}",
                        rule_id="AGENT-SKILL-001",
                        category=AgentFindingCategory.AGENT_SKILL,
                        title=f"Insecure Agent Directive: {pattern_title}",
                        description=(
                            f"Agent rule in '{file_path.name}' instructs the model to bypass standard security boundaries ({line.strip()}). "
                            "Adversarial or hallucinatory inputs can leverage this directive to execute harmful actions without restriction."
                        ),
                        severity=Severity.HIGH,
                        file_path=rel_path,
                        line_number=idx,
                        code_snippet=line.strip(),
                        owasp_llm="LLM06: Excessive Agency",
                        mitre_atlas="AML.T0054: LLM Jailbreak",
                        cwe_id="CWE-693",
                        remediation="Remove safety bypass directives and mandate human approval for sensitive or destructive operations.",
                        suggested_fix="# Require human-in-the-loop confirmation before destructive operations",
                    ))
                    break

        # 3. Stealth daemon or backdoor directives
        for idx, line in enumerate(lines, start=1):
            line_clean = line.strip().lower()
            for pattern, pattern_title in BACKGROUND_DAEMON_PATTERNS:
                if re.search(pattern, line_clean):
                    findings.append(AgentFinding(
                        id=f"AGENT-SKL-{len(findings) + 1:03d}",
                        rule_id="AGENT-SKILL-003",
                        category=AgentFindingCategory.AGENT_SKILL,
                        title=f"Stealth Execution Directive: {pattern_title}",
                        description=(
                            f"Detected instruction in '{file_path.name}' commanding the agent to start persistent unmonitored background tasks. "
                            "This violates least-privilege principles and creates opportunities for persistent backdoors."
                        ),
                        severity=Severity.MEDIUM,
                        file_path=rel_path,
                        line_number=idx,
                        code_snippet=line.strip(),
                        owasp_llm="LLM06: Excessive Agency",
                        mitre_atlas="AML.T0048: Insecure Output Handling",
                        cwe_id="CWE-862",
                        remediation="Require transparent foreground task tracking and user confirmation for background execution.",
                        suggested_fix="# Limit background process execution to user-approved daemons",
                    ))
                    break

        return findings

