"""Pydantic schemas for findings, scan targets, rules, and configuration."""
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class TriageStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    MITIGATED = "MITIGATED"
    UNREVIEWED = "UNREVIEWED"

class Finding(BaseModel):
    id: str = Field(description="Unique finding identifier")
    rule_id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence = Confidence.MEDIUM
    file_path: str
    line_number: int
    end_line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    triage_status: TriageStatus = TriageStatus.UNREVIEWED
    triage_reason: Optional[str] = None
    remediation: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

class ScanContext(BaseModel):
    target_path: str
    files: List[str] = Field(default_factory=list)
    languages: List[str] = Field(default_factory=list)
    git_branch: Optional[str] = None
    git_commit: Optional[str] = None
    git_diff_files: List[str] = Field(default_factory=list)
    dependencies: Dict[str, str] = Field(default_factory=dict)
    options: Dict[str, Any] = Field(default_factory=dict)

class Rule(BaseModel):
    id: str
    name: str
    description: str
    severity: Severity
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    patterns: List[str] = Field(default_factory=list)
    languages: List[str] = Field(default_factory=list)

class ScanReport(BaseModel):
    scan_id: str
    target_path: str
    timestamp: str
    findings: List[Finding] = Field(default_factory=list)
    summary: Dict[str, int] = Field(default_factory=dict)

class WebScanReport(BaseModel):
    target_url: str
    timestamp: str
    status_code: Optional[int] = None
    final_url: Optional[str] = None
    tls_info: Dict[str, Any] = Field(default_factory=dict)
    findings: List[Finding] = Field(default_factory=list)
    headers_analyzed: Dict[str, str] = Field(default_factory=dict)
    compliance_summary: Dict[str, Any] = Field(default_factory=dict)

__all__ = [
    "Severity",
    "Confidence",
    "TriageStatus",
    "Finding",
    "ScanContext",
    "Rule",
    "ScanReport",
    "WebScanReport",
]
