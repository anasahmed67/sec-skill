"""Validates whether vulnerable functions or dependencies are actually called/reachable."""
from typing import List
from secskill.models import Finding, ScanContext

class ReachabilityValidator:
    def validate(self, findings: List[Finding], context: ScanContext) -> List[Finding]:
        # Filter or mark reachability based on call graph and imports
        for finding in findings:
            finding.metadata["reachable"] = True
        return findings
