"""Checks for existing framework-level sanitizers or defensive controls."""
from typing import List
from secskill.models import Finding, ScanContext, TriageStatus

class MitigationChecker:
    def check_mitigations(self, findings: List[Finding], context: ScanContext) -> List[Finding]:
        for finding in findings:
            # Check if mitigation exists (e.g. CSRF protection enabled in settings)
            if "csrf" in finding.title.lower() and "django.middleware.csrf.CsrfViewMiddleware" in str(context.files):
                finding.triage_status = TriageStatus.MITIGATED
                finding.triage_reason = "CSRF middleware detected globally."
        return findings
