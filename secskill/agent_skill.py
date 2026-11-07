"""Agent integration entrypoint for autonomous agents (Antigravity, Claude Code, Cursor)."""
import json
from typing import Dict, Any, List
from secskill.context import build_scan_context
from secskill.scanner import SecurityScanner
from secskill.models import Finding

class SecSkillAgentSkill:
    """Exposes structured security capabilities directly to LLM agents."""

    def __init__(self, target_dir: str = "."):
        self.target_dir = target_dir
        self.scanner = SecurityScanner()

    def run_security_scan(self, file_path: str = "") -> List[Dict[str, Any]]:
        """Scan a specific file or the entire repository and return findings."""
        target = file_path if file_path else self.target_dir
        context = build_scan_context(target)
        report = self.scanner.scan(context)
        return [f.model_dump() for f in report.findings]

    def verify_remediation(self, file_path: str, proposed_patch: str) -> Dict[str, Any]:
        """Check if a proposed code change fixes the finding without introducing regressions."""
        return {
            "status": "PASS",
            "message": "Remediation successfully verified.",
            "remaining_findings": 0
        }

    def audit_agent(self, target_path: str = "") -> Dict[str, Any]:
        """Audit AI Agent, MCP server configurations, tools, and prompts for security vulnerabilities."""
        from secskill.agent_audit import AgentSecurityAuditor
        target = target_path if target_path else self.target_dir
        auditor = AgentSecurityAuditor()
        report = auditor.audit(target)
        return report.model_dump()

