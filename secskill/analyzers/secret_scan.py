"""Secret and credential scanning analyzer."""
import re
from pathlib import Path
from typing import List
from secskill.analyzers.base import BaseAnalyzer
from secskill.models import ScanContext, Finding, Severity, Confidence

class SecretAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str:
        return "SecretAnalyzer"

    def analyze(self, context: ScanContext) -> List[Finding]:
        findings = []
        root = Path(context.target_path)
        base_dir = root.parent if root.is_file() else root

        secret_regexes = [
            (r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}", "SEC-SECRET-001", "Hardcoded AWS Access Key", Severity.CRITICAL, "CWE-798"),
            (r"(?i)api[_-]?key\s*=\s*['\"][A-Za-z0-9_\-]{16,}['\"]", "SEC-SECRET-002", "Hardcoded API Key", Severity.CRITICAL, "CWE-798"),
            (r"(?i)password\s*=\s*['\"][^'\"]{6,}['\"]", "SEC-SECRET-003", "Hardcoded Password", Severity.HIGH, "CWE-259"),
            (r"-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----", "SEC-SECRET-004", "Private Key Disclosed", Severity.CRITICAL, "CWE-321"),
            (r"(?:ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z_]{36}", "SEC-SECRET-005", "GitHub Personal Access Token", Severity.CRITICAL, "CWE-798"),
        ]

        for file_rel in context.files:
            file_path = base_dir / file_rel
            if not file_path.is_file():
                continue
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                for line_idx, line in enumerate(content.splitlines(), 1):
                    # Skip test allowlists
                    if any(w in line.lower() for w in ["example", "sample", "dummy", "placeholder", "test"]):
                        continue
                    for regex, rule_id, title, sev, cwe in secret_regexes:
                        if re.search(regex, line):
                            findings.append(
                                Finding(
                                    id=f"{rule_id}-{file_rel}-{line_idx}",
                                    rule_id=rule_id,
                                    title=title,
                                    description="Exposed hardcoded secret or credential token.",
                                    severity=sev,
                                    confidence=Confidence.HIGH,
                                    file_path=file_rel,
                                    line_number=line_idx,
                                    code_snippet="*** REDACTED ***",
                                    cwe_id=cwe,
                                )
                            )
            except Exception:
                continue
        return findings
