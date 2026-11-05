"""Dependency vulnerability analyzer."""
from pathlib import Path
from typing import List
from secskill.analyzers.base import BaseAnalyzer
from secskill.models import ScanContext, Finding, Severity, Confidence

class DependencyAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str:
        return "DependencyAnalyzer"

    def analyze(self, context: ScanContext) -> List[Finding]:
        findings = []
        root = Path(context.target_path)

        # Check Python requirements
        req_file = root / "requirements.txt"
        if req_file.exists():
            for line_idx, line in enumerate(req_file.read_text(encoding="utf-8").splitlines(), 1):
                clean = line.strip().lower()
                if "requests==2.6.0" in clean or "urllib3==1.24.1" in clean:
                    findings.append(
                        Finding(
                            id=f"DEP-PY-{line_idx}",
                            rule_id="DEP-VULN-001",
                            title="Vulnerable Dependency Version",
                            description=f"Known CVE associated with dependency: {clean}",
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            file_path="requirements.txt",
                            line_number=line_idx,
                            code_snippet=line.strip(),
                            cwe_id="CWE-1395",
                        )
                    )
        return findings
