"""Agent integration entrypoint for autonomous agents (Antigravity, Claude Code, Cursor, Codex)."""
import tempfile
from pathlib import Path
from typing import Dict, Any, List, Optional
from secskill.context import build_scan_context
from secskill.scanner import SecurityScanner
from secskill.analyzers.web_scan import WebSecurityScanner

class SecSkillAgentSkill:
    """Exposes structured security capabilities directly to LLM agents."""

    def __init__(self, target_dir: str = "."):
        self.target_dir = target_dir
        self.scanner = SecurityScanner()
        self.web_scanner = WebSecurityScanner()

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
        """
        Verify whether a proposed code change fixes the finding without introducing regressions.
        Scans baseline code, applies virtual patch, scans patched code, and compares finding states.
        """
        fpath = Path(file_path)
        ext = fpath.suffix if fpath.suffix else ".py"

        # 1. Obtain baseline content
        if original_code is not None:
            orig_text = original_code
        elif fpath.is_file():
            try:
                orig_text = fpath.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                orig_text = ""
        else:
            orig_text = ""

        # 2. Determine patched content
        patched_text = self._apply_patch_or_content(orig_text, proposed_patch)

        # 3. Create temp isolated environment to scan baseline and patched
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            orig_file = temp_path / f"original{ext}"
            patched_file = temp_path / f"patched{ext}"

            orig_file.write_text(orig_text, encoding="utf-8")
            patched_file.write_text(patched_text, encoding="utf-8")

            # Scan baseline
            ctx_orig = build_scan_context(str(orig_file))
            rep_orig = self.scanner.scan(ctx_orig)
            baseline_findings = rep_orig.findings

            # Scan patched
            ctx_patched = build_scan_context(str(patched_file))
            rep_patched = self.scanner.scan(ctx_patched)
            patched_findings = rep_patched.findings

        # 4. Compare findings
        baseline_rules = {f.rule_id for f in baseline_findings}
        patched_rules = {f.rule_id for f in patched_findings}

        resolved = [f.model_dump() for f in baseline_findings if f.rule_id not in patched_rules]
        remaining = [f.model_dump() for f in patched_findings if f.rule_id in baseline_rules]
        regressions = [f.model_dump() for f in patched_findings if f.rule_id not in baseline_rules]

        # 5. Determine verification verdict
        if regressions:
            status = "REGRESSION"
            message = f"Remediation introduced {len(regressions)} new vulnerability regression(s)!"
        elif remaining and not resolved:
            status = "FAIL"
            message = f"Vulnerability not resolved: {len(remaining)} finding(s) still present in patched code."
        elif remaining and resolved:
            status = "PARTIAL"
            message = f"Partially resolved {len(resolved)} finding(s), but {len(remaining)} finding(s) remain."
        else:
            status = "PASS"
            message = f"Remediation successfully verified. {len(resolved)} finding(s) neutralized with 0 regressions."

        return {
            "status": status,
            "message": message,
            "baseline_count": len(baseline_findings),
            "remaining_count": len(remaining),
            "resolved_count": len(resolved),
            "regression_count": len(regressions),
            "resolved_findings": resolved,
            "remaining_findings": remaining,
            "new_regressions": regressions,
        }

    def _apply_patch_or_content(self, original: str, patch_or_content: str) -> str:
        """Helper to extract clean replacement content from full file or unified diff."""
        patch_clean = patch_or_content.strip()

        # If it looks like a unified diff
        if "@@" in patch_clean or patch_clean.startswith("--- ") or patch_clean.startswith("+++ "):
            lines_orig = original.splitlines()
            diff_lines = patch_clean.splitlines()

            # Extract lines being added and deleted
            added_lines = []
            deleted_lines = []
            for dl in diff_lines:
                if dl.startswith("+") and not dl.startswith("+++"):
                    added_lines.append(dl[1:].strip())
                elif dl.startswith("-") and not dl.startswith("---"):
                    deleted_lines.append(dl[1:].strip())

            # Attempt simple line replacement
            new_lines = []
            applied = False
            for line in lines_orig:
                line_stripped = line.strip()
                if line_stripped in deleted_lines and not applied:
                    for al in added_lines:
                        indent = len(line) - len(line.lstrip())
                        new_lines.append((" " * indent) + al)
                    applied = True
                else:
                    new_lines.append(line)

            if applied:
                return "\n".join(new_lines) + "\n"

        # If not a diff or diff application failed, treat patch_or_content as full replacement code
        return patch_or_content

    def audit_agent(self, target_path: str = "") -> Dict[str, Any]:
        """Audit AI Agent, MCP server configurations, tools, and prompts for security vulnerabilities."""
        from secskill.agent_audit import AgentSecurityAuditor
        target = target_path if target_path else self.target_dir
        auditor = AgentSecurityAuditor()
        report = auditor.audit(target)
        return report.model_dump()
