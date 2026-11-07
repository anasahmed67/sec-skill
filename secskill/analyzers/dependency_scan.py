"""Dependency vulnerability analyzer."""
from pathlib import Path
from typing import List
from secskill.analyzers.base import BaseAnalyzer
from secskill.models import ScanContext, Finding, Severity, Confidence
from secskill.scripts.dep_scan import scan_dependencies

SEV_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
}

class DependencyAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str:
        return "DependencyAnalyzer"

    def analyze(self, context: ScanContext) -> List[Finding]:
        findings = []
        root = Path(context.target_path)
        base_dir = root.parent if root.is_file() else root
        allow_network = bool(context.options.get("consent", False))

        # Run the full dependency audit
        raw_findings = scan_dependencies(str(base_dir), allow_network=allow_network)

        for rf in raw_findings:
            sev_str = str(rf.get("severity", "HIGH")).lower()
            sev = SEV_MAP.get(sev_str, Severity.HIGH)
            f_id = rf.get("finding_id", "DEP-VULN-001")
            file_abs = rf.get("file", "requirements.txt")
            try:
                file_rel = Path(file_abs).relative_to(base_dir).as_posix()
            except Exception:
                file_rel = Path(file_abs).name

            pkg_name = rf.get("metadata", {}).get("package", "dependency")
            fixed_ver = rf.get("metadata", {}).get("fixed_version", "latest secure release")

            findings.append(
                Finding(
                    id=f_id,
                    rule_id="DEP-VULN-001",
                    title=rf.get("title", f"Vulnerable Dependency: {pkg_name}"),
                    description=rf.get("evidence", "Known CVE in dependency"),
                    severity=sev,
                    confidence=Confidence.HIGH,
                    file_path=file_rel,
                    line_number=rf.get("line", 1),
                    code_snippet=rf.get("evidence", ""),
                    cwe_id=rf.get("cwe", "CWE-1395"),
                    owasp_category=rf.get("owasp", "A06:2021-Vulnerable and Outdated Components"),
                    remediation=f"Upgrade package '{pkg_name}' to version {fixed_ver} or higher.",
                    metadata=rf.get("metadata", {}),
                )
            )

        return findings
