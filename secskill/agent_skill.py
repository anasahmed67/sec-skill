"""Agent integration entrypoint for autonomous agents (Antigravity, Claude Code, Cursor, Codex)."""
import tempfile
from pathlib import Path
from typing import Dict, Any, List, Optional
from secskill.context import build_scan_context
from secskill.scanner import SecurityScanner
from secskill.analyzers.web_scan import WebSecurityScanner
from secskill.services.remediation import RemediationVerifier

class SecSkillAgentSkill:
    """Exposes structured security capabilities directly to LLM agents."""

    def __init__(self, target_dir: str = "."):
        self.target_dir = target_dir
        self.scanner = SecurityScanner()
        self.web_scanner = WebSecurityScanner()
        self.remediation_verifier = RemediationVerifier(self.scanner)

    def run_security_scan(
        self,
        file_path: str = "",
        extra_ignores: Optional[List[str]] = None,
        include_secskill: bool = False,
    ) -> List[Dict[str, Any]]:
        """Scan a specific file or the entire repository and return findings."""
        target = file_path if file_path else self.target_dir
        context = build_scan_context(
            target, extra_ignores=extra_ignores, include_secskill=include_secskill
        )
        report = self.scanner.scan(context)
        return [f.model_dump() for f in report.findings]

    def scan_url(self, url: str, check_sensitive_paths: bool = True) -> Dict[str, Any]:
        """Audit live website or API endpoint against international security standards."""
        report = self.web_scanner.scan_url(url, check_sensitive_paths=check_sensitive_paths)
        return report.model_dump()

    def verify_remediation(
        self,
        file_path: str,
        proposed_patch: str,
        original_code: Optional[str] = None
    ) -> Dict[str, Any]:
        """Verify whether a proposed code change fixes the finding without introducing regressions.
        
        Scans baseline code, applies virtual patch, scans patched code, and compares finding states.
        """
        return self.remediation_verifier.verify(
            file_path=file_path,
            proposed_patch=proposed_patch,
            original_code=original_code,
        )

    def _apply_patch_or_content(self, original: str, patch_or_content: str) -> str:
        """Helper to extract clean replacement content from full file or unified diff."""
        return RemediationVerifier.apply_patch_or_content(original, patch_or_content)

    def audit_agent(self, target_path: str = "") -> Dict[str, Any]:
        """Audit AI Agent, MCP server configurations, tools, and prompts for security vulnerabilities."""
        from secskill.agent_audit import AgentSecurityAuditor
        target = target_path if target_path else self.target_dir
        auditor = AgentSecurityAuditor()
        report = auditor.audit(target)
        return report.model_dump()
