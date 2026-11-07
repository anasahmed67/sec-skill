"""Data models and schemas for AI Agent & MCP Security Auditing."""
from enum import Enum
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from secskill.models import Severity, Finding, Confidence, TriageStatus

class AgentFindingCategory(str, Enum):
    MCP_CONFIG = "MCP Configuration"
    AGENT_TOOL = "Agent Tool Safety"
    PROMPT_ARCHITECTURE = "Prompt Architecture"
    AGENT_SKILL = "Agent Skill & Rules"

class AgentFinding(BaseModel):
    """Specialized security finding for AI Agents and MCP Servers."""
    id: str = Field(description="Unique agent finding ID (e.g. AGENT-MCP-001)")
    rule_id: str
    category: AgentFindingCategory
    title: str
    description: str
    severity: Severity
    file_path: str
    line_number: int = 1
    end_line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    owasp_llm: str = "LLM06: Excessive Agency"
    mitre_atlas: str = "AML.T0048: Insecure Output Handling"
    cwe_id: str = "CWE-862"
    remediation: str
    suggested_fix: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def to_standard_finding(self) -> Finding:
        """Convert to SecSkill core Finding for unified SARIF/JSON reporting."""
        return Finding(
            id=self.id,
            rule_id=self.rule_id,
            title=self.title,
            description=f"[{self.owasp_llm}] {self.description}",
            severity=self.severity,
            confidence=Confidence.HIGH,
            file_path=self.file_path,
            line_number=self.line_number,
            end_line_number=self.end_line_number,
            code_snippet=self.code_snippet,
            cwe_id=self.cwe_id,
            owasp_category=self.owasp_llm,
            triage_status=TriageStatus.CONFIRMED,
            remediation=self.remediation,
            metadata={
                "category": self.category.value,
                "owasp_llm": self.owasp_llm,
                "mitre_atlas": self.mitre_atlas,
                "suggested_fix": self.suggested_fix,
                **self.metadata,
            },
        )

class McpServerInfo(BaseModel):
    """Discovered MCP Server configuration entry."""
    server_name: str
    source_file: str
    command: str
    args: List[str] = Field(default_factory=list)
    has_shell_access: bool = False
    has_filesystem_root: bool = False
    has_raw_env_secrets: bool = False
    is_pinned: bool = True
    transport: str = "stdio"
    risk_level: Severity = Severity.LOW

class AgentAuditStats(BaseModel):
    """Aggregate statistics for an Agent & MCP audit."""
    mcp_configs_scanned: int = 0
    mcp_servers_found: int = 0
    agent_tools_scanned: int = 0
    prompt_templates_scanned: int = 0
    skill_files_scanned: int = 0
    total_files_audited: int = 0

class AgentAuditReport(BaseModel):
    """Full comprehensive report of AI Agent & MCP Security Audit."""
    scan_id: str
    target_path: str
    timestamp: str
    stats: AgentAuditStats
    mcp_servers: List[McpServerInfo] = Field(default_factory=list)
    findings: List[AgentFinding] = Field(default_factory=list)
    security_score: int = 100
    grade: str = "A+"
    summary: Dict[str, int] = Field(default_factory=dict)
    owasp_llm_summary: Dict[str, int] = Field(default_factory=dict)

