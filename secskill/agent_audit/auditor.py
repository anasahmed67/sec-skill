"""Orchestrator for AI Agent and MCP Security Audits."""
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from secskill.models import Severity, ScanReport
from secskill.agent_audit.models import (
    AgentFinding,
    McpServerInfo,
    AgentAuditStats,
    AgentAuditReport,
)
from secskill.agent_audit.mcp_analyzer import McpConfigAnalyzer
from secskill.agent_audit.tool_analyzer import AgentToolAnalyzer, is_tool_candidate
from secskill.agent_audit.prompt_analyzer import PromptArchitectureAnalyzer
from secskill.agent_audit.skill_analyzer import AgentSkillAnalyzer
from secskill.agent_audit.html_report import AgentAuditHtmlReporter

console = Console()

class AgentSecurityAuditor:
    """Full-spectrum auditor for MCP servers, Agent Tools, Prompt Sinks, and Skills."""

    def __init__(self):
        self.mcp_analyzer = McpConfigAnalyzer()
        self.tool_analyzer = AgentToolAnalyzer()
        self.prompt_analyzer = PromptArchitectureAnalyzer()
        self.skill_analyzer = AgentSkillAnalyzer()

    def audit(self, target_path: str) -> AgentAuditReport:
        root = Path(target_path).resolve()
        stats = AgentAuditStats()
        findings: List[AgentFinding] = []
        mcp_servers: List[McpServerInfo] = []

        all_files: List[Path] = []
        if root.is_file():
            all_files = [root]
        else:
            # Skip noise directories
            ignore_parts = {".git", "node_modules", "venv", ".venv", "__pycache__", ".pytest_cache", ".ruff_cache", "dist", "build"}
            for p in root.rglob("*"):
                if p.is_file() and not any(part in ignore_parts for part in p.parts):
                    all_files.append(p)

        stats.total_files_audited = len(all_files)

        for f in all_files:
            fname = f.name.lower()
            suffix = f.suffix.lower()

            # 1. MCP Configuration Analysis
            if self.mcp_analyzer.is_mcp_config(f):
                stats.mcp_configs_scanned += 1
                mcp_finds, servers = self.mcp_analyzer.analyze_file(f)
                findings.extend(mcp_finds)
                mcp_servers.extend(servers)
                stats.mcp_servers_found += len(servers)

            # 2. Agent Skill & Rules Analysis
            elif self.skill_analyzer.is_skill_file(f):
                stats.skill_files_scanned += 1
                findings.extend(self.skill_analyzer.analyze_file(f))

            # 3. Agent Tool & Code Analysis
            elif suffix in {".py", ".js", ".ts", ".mjs", ".tsx"}:
                if is_tool_candidate(f):
                    stats.agent_tools_scanned += 1
                    findings.extend(self.tool_analyzer.analyze_file(f))

                # Check prompt architectures in code as well
                prompt_finds = self.prompt_analyzer.analyze_file(f)
                if prompt_finds:
                    stats.prompt_templates_scanned += 1
                    findings.extend(prompt_finds)

            # 4. Standalone Prompt & Template Files
            elif suffix in {".prompt", ".jinja", ".jinja2"}:
                stats.prompt_templates_scanned += 1
                findings.extend(self.prompt_analyzer.analyze_file(f))

        # Summaries
        summary: Dict[str, int] = {s.value: 0 for s in Severity}
        owasp_summary: Dict[str, int] = {}
        for f in findings:
            summary[f.severity.value] = summary.get(f.severity.value, 0) + 1
            owasp_k = f.owasp_llm
            owasp_summary[owasp_k] = owasp_summary.get(owasp_k, 0) + 1

        # Calculate Security Score
        score = 100
        score -= summary.get("CRITICAL", 0) * 25
        score -= summary.get("HIGH", 0) * 12
        score -= summary.get("MEDIUM", 0) * 5
        score -= summary.get("LOW", 0) * 2
        score = max(0, min(100, score))

        if score >= 95:
            grade = "A+"
        elif score >= 90:
            grade = "A"
        elif score >= 80:
            grade = "B"
        elif score >= 70:
            grade = "C"
        elif score >= 50:
            grade = "D"
        else:
            grade = "F"

        return AgentAuditReport(
            scan_id=str(uuid.uuid4()),
            target_path=str(root).replace("\\", "/"),
            timestamp=datetime.now(timezone.utc).isoformat(),
            stats=stats,
            mcp_servers=mcp_servers,
            findings=findings,
            security_score=score,
            grade=grade,
            summary=summary,
            owasp_llm_summary=owasp_summary,
        )

    def render_console(self, report: AgentAuditReport) -> None:
        """Render flashy Rich terminal report."""
        # Cyber Banner
        banner_text = Text()
        banner_text.append("╔═══════════════════════════════════════════════════════════════════════════╗\n", style="bold cyan")
        banner_text.append("║                   ", style="bold cyan")
        banner_text.append("SecSkill AI Agent & MCP Security Auditor", style="bold white")
        banner_text.append("                ║\n", style="bold cyan")
        banner_text.append("║           OWASP Top 10 for LLM & MITRE ATLAS Compliance Engine            ║\n", style="dim cyan")
        banner_text.append("╚═══════════════════════════════════════════════════════════════════════════╝", style="bold cyan")
        console.print(banner_text)

        # Score and Target Panel
        score_color = "bold green" if report.security_score >= 80 else ("bold yellow" if report.security_score >= 60 else "bold red")
        score_panel = Panel(
            f"[bold white]Target Scope:[/bold white] [cyan]{report.target_path}[/cyan]\n"
            f"[bold white]Trust Index:[/bold white] [{score_color}]{report.security_score} / 100[/{score_color}] "
            f"([bold white]Grade:[/bold white] [{score_color}]{report.grade}[/{score_color}])\n"
            f"[bold white]Scope Inspected:[/bold white] {report.stats.mcp_servers_found} MCP Servers | "
            f"{report.stats.agent_tools_scanned} Tool Defs | {report.stats.prompt_templates_scanned} Prompts | "
            f"{report.stats.skill_files_scanned} Skills",
            title="[bold green]Security Posture Overview[/bold green]",
            border_style="green" if report.security_score >= 80 else "red",
        )
        console.print(score_panel)

        # MCP Server Matrix Table (if any found)
        if report.mcp_servers:
            console.print("\n[bold cyan]=== Model Context Protocol (MCP) Server Trust Matrix ===[/bold cyan]\n")
            mcp_table = Table(show_header=True, header_style="bold magenta")
            mcp_table.add_column("Server", style="cyan", width=18)
            mcp_table.add_column("Command", style="white", width=22)
            mcp_table.add_column("Host Shell", style="bold red", width=12)
            mcp_table.add_column("Root FS", style="yellow", width=14)
            mcp_table.add_column("Env Secrets", style="bold yellow", width=14)
            mcp_table.add_column("Version Pin", style="green", width=12)
            mcp_table.add_column("Risk", style="bold")

            for s in report.mcp_servers:
                shell_str = "[bold red]EXPOSED[/bold red]" if s.has_shell_access else "[green]RESTRICTED[/green]"
                root_str = "[yellow]ROOT/HOME[/yellow]" if s.has_filesystem_root else "[green]SCOPED[/green]"
                sec_str = "[bold red]EXPOSED[/bold red]" if s.has_raw_env_secrets else "[green]SECURE[/green]"
                pin_str = "[green]PINNED[/green]" if s.is_pinned else "[yellow]UNPINNED[/yellow]"
                risk_style = "bold red" if s.risk_level == Severity.CRITICAL else ("bold yellow" if s.risk_level == Severity.HIGH else "green")
                mcp_table.add_row(
                    s.server_name,
                    s.command[:20] + ("..." if len(s.command) > 20 else ""),
                    shell_str,
                    root_str,
                    sec_str,
                    pin_str,
                    f"[{risk_style}]{s.risk_level.value}[/{risk_style}]",
                )
            console.print(mcp_table)

        # Findings Section
        if not report.findings:
            console.print("\n[bold green]✓ Zero security violations detected across Agent and MCP definitions![/bold green]\n")
            return

        console.print(f"\n[bold red]=== Detected Security Findings ({len(report.findings)}) ===[/bold red]\n")
        for f in report.findings:
            sev_color = "bold red" if f.severity == Severity.CRITICAL else ("bold yellow" if f.severity == Severity.HIGH else "cyan")
            sev_tag = f"[{sev_color}][{f.severity.value}][/{sev_color}]"

            content_lines = [
                f"{sev_tag} [bold white]{f.title}[/bold white] ({f.rule_id})",
                f"[dim]File:[/dim] [cyan]{f.file_path}:{f.line_number}[/cyan]",
                f"[dim]OWASP LLM:[/dim] [magenta]{f.owasp_llm}[/magenta] | [dim]MITRE ATLAS:[/dim] [blue]{f.mitre_atlas}[/blue] | [dim]CWE:[/dim] [yellow]{f.cwe_id}[/yellow]",
                f"\n[bold]Description:[/bold] {f.description}",
            ]
            if f.code_snippet:
                content_lines.append(f"\n[bold yellow]Context Snippet:[/bold yellow]\n  [dim]{f.code_snippet}[/dim]")
            content_lines.append(f"\n[bold green]Remediation:[/bold green] {f.remediation}")
            if f.suggested_fix:
                content_lines.append(f"[bold cyan]Proposed Patch:[/bold cyan] [dim]{f.suggested_fix}[/dim]")

            console.print(Panel(
                "\n".join(content_lines),
                border_style="red" if f.severity in [Severity.CRITICAL, Severity.HIGH] else "yellow",
                expand=False,
            ))

        # Bottom Summary
        console.print(Panel(
            f"[bold white]Summary:[/bold white] "
            f"[bold red]{report.summary.get('CRITICAL', 0)} Critical[/bold red] | "
            f"[bold yellow]{report.summary.get('HIGH', 0)} High[/bold yellow] | "
            f"[bold cyan]{report.summary.get('MEDIUM', 0)} Medium[/bold cyan] | "
            f"[green]{report.summary.get('LOW', 0)} Low[/green]\n"
            f"[dim]Tip: Generate interactive visual dashboard using: secskill audit-agent --format html --open[/dim]",
            title="[bold cyan]SecSkill Audit Complete[/bold cyan]",
            border_style="cyan",
        ))

    def export_sarif(self, report: AgentAuditReport, output_path: Optional[Path] = None) -> str:
        """Export to OASIS SARIF 2.1.0."""
        # Convert AgentFindings to core Findings to reuse standard SARIF reporter
        core_findings = [f.to_standard_finding() for f in report.findings]
        scan_report = ScanReport(
            scan_id=report.scan_id,
            target_path=report.target_path,
            timestamp=report.timestamp,
            findings=core_findings,
            summary=report.summary,
        )
        from secskill.reporting.sarif_report import SarifReporter
        return SarifReporter().generate(scan_report, output_path)

    def export_json(self, report: AgentAuditReport, output_path: Optional[Path] = None) -> str:
        """Export full structured JSON report."""
        data = report.model_dump()
        text = json.dumps(data, indent=2)
        if output_path:
            output_path.write_text(text, encoding="utf-8")
        return text

    def export_html(self, report: AgentAuditReport, output_path: Optional[Path] = None) -> str:
        """Export interactive Cyberpunk HTML dashboard."""
        return AgentAuditHtmlReporter.generate(report, output_path)
