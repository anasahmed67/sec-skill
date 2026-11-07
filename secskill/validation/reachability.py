"""Validates whether vulnerable functions, sinks, or dependencies are actually reachable in application code."""
import re
from pathlib import Path
from typing import List
from secskill.models import Finding, ScanContext, Confidence

class ReachabilityValidator:
    """Evaluates reachability of findings based on project structure, entry points, and test file boundaries."""

    TEST_PATTERNS = [
        r"tests?[/\\_]",
        r"spec[/\\_]",
        r"mock[/\\_]",
        r"fixtures?[/\\_]",
        r"examples?[/\\_]",
        r"test_[^/\\]+\.py$",
        r"[^/\\]+_test\.[a-z]+$",
    ]

    ENTRYPOINT_PATTERNS = [
        r"@(?:app|router|blueprint)\.(?:route|get|post|put|delete|patch)\(",
        r"@api_view\(",
        r"def\s+main\s*\(",
        r"if\s+__name__\s*==\s*['\"]__main__['\"]:",
        r"public\s+static\s+void\s+main\(",
        r"export\s+default\s+function",
        r"app\.(?:get|post|put|delete|use)\(",
    ]

    def validate(self, findings: List[Finding], context: ScanContext) -> List[Finding]:
        root = Path(context.target_path)
        base_dir = root.parent if root.is_file() else root

        for finding in findings:
            fpath = finding.file_path.replace("\\", "/")

            # 1. Check if finding is situated in test/mock/example code
            is_test = any(re.search(pat, fpath, re.IGNORECASE) for pat in self.TEST_PATTERNS)
            if is_test:
                finding.metadata["in_test_file"] = True
                finding.metadata["reachable"] = False
                finding.metadata["reachability_assessment"] = "test_or_mock_code"
                # Downgrade confidence for mock flaws in test code
                if finding.confidence == Confidence.HIGH:
                    finding.confidence = Confidence.MEDIUM
                continue

            # 2. Check if finding resides in or near an active entrypoint
            target_file = base_dir / finding.file_path
            is_entrypoint = False
            if target_file.is_file():
                try:
                    content = target_file.read_text(encoding="utf-8", errors="ignore")
                    is_entrypoint = any(re.search(pat, content) for pat in self.ENTRYPOINT_PATTERNS)
                except Exception:
                    pass

            if is_entrypoint:
                finding.metadata["reachable"] = True
                finding.metadata["entrypoint_reachable"] = True
                finding.metadata["reachability_assessment"] = "confirmed_entrypoint_or_route"
            else:
                finding.metadata["reachable"] = True
                finding.metadata["reachability_assessment"] = "source_file_reachable"

        return findings
