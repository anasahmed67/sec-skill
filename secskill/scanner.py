"""Pipeline orchestrator running Analyzers -> Validation -> LLM Review."""
import uuid
from datetime import datetime, timezone
from typing import List, Optional
from secskill.models import ScanContext, ScanReport, Finding, Severity
from secskill.analyzers.base import BaseAnalyzer
from secskill.analyzers.static_analysis import StaticAnalyzer
from secskill.analyzers.secret_scan import SecretAnalyzer
from secskill.analyzers.dependency_scan import DependencyAnalyzer
from secskill.analyzers.dataflow import DataflowAnalyzer
from secskill.validation.filter import FindingFilter
from secskill.validation.reachability import ReachabilityValidator

class SecurityScanner:
    """Core SAST analysis pipeline orchestrator.
    
    Coordinates analyzers, deduplication/ignore filtering, reachability analysis,
    and optional LLM contextual triage into a cohesive ScanReport.
    """

    def __init__(
        self,
        enable_llm: bool = False,
        provider_name: str = "ollama",
        analyzers: Optional[List[BaseAnalyzer]] = None,
        filter_engine: Optional[FindingFilter] = None,
        reachability_validator: Optional[ReachabilityValidator] = None,
    ):
        self.analyzers: List[BaseAnalyzer] = analyzers if analyzers is not None else [
            StaticAnalyzer(),
            SecretAnalyzer(),
            DependencyAnalyzer(),
            DataflowAnalyzer(),
        ]
        self.filter = filter_engine or FindingFilter()
        self.reachability = reachability_validator or ReachabilityValidator()
        self.enable_llm = enable_llm
        self.provider_name = provider_name

    def scan(self, context: ScanContext) -> ScanReport:
        raw_findings: List[Finding] = []
        for analyzer in self.analyzers:
            raw_findings.extend(analyzer.analyze(context))

        validated_findings = self.filter.apply(raw_findings, context)
        validated_findings = self.reachability.validate(validated_findings, context)

        # 3. LLM Contextual Triage (if enabled)
        if self.enable_llm:
            try:
                from secskill.llm.reviewer import ContextualReviewer
                reviewer = ContextualReviewer(provider_name=self.provider_name)
                validated_findings = reviewer.triage_findings(validated_findings, context)
            except Exception:
                pass

        # Summary counts
        summary = {sev.value: 0 for sev in Severity}
        for f in validated_findings:
            summary[f.severity.value] = summary.get(f.severity.value, 0) + 1

        return ScanReport(
            scan_id=str(uuid.uuid4()),
            target_path=context.target_path,
            timestamp=datetime.now(timezone.utc).isoformat(),
            findings=validated_findings,
            summary=summary,
        )
