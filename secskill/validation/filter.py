"""Suppression comments (# secskill:ignore) and exclusion filters."""
from typing import List
from secskill.models import Finding, ScanContext

class FindingFilter:
    def apply(self, findings: List[Finding], context: ScanContext) -> List[Finding]:
        filtered = []
        for finding in findings:
            if finding.code_snippet and "secskill:ignore" in finding.code_snippet:
                continue
            filtered.append(finding)
        return filtered
