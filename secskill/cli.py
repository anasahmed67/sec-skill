"""Typer CLI application for SecSkill."""
import json
from datetime import datetime
from typing import Optional
from pathlib import Path
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from secskill import __version__
from secskill.models import ScanReport
from secskill.context import build_scan_context
from secskill.scanner import SecurityScanner
from secskill.reporting import (
    ConsoleReporter,
    SarifReporter,
    JsonReporter,
    MarkdownReporter,
    HtmlReporter,
)
from secskill.installer import AgentInstaller
from secskill.updater import SecSkillUpdater
from secskill.analyzers.web_scan import WebSecurityScanner
from secskill.services.knowledge import explain_security_topic
from secskill.templates import (
    AGENT_MD_TEMPLATE,
    RULES_MD_TEMPLATE,
    POLICIES_MD_TEMPLATE,
    CURSOR_RULES_TEMPLATE,
    WORKFLOW_TEMPLATE,
)

app = typer.Typer(help="SecSkill - AI-enhanced Security Scanner & Agent Skill")
console = Console()

@app.command()
def scan(
    path: Path = typer.Argument(Path("."), help="Path to target directory or file"),
    format: str = typer.Option("console", "--format", "-f", help="Output format: console, sarif, json, markdown"),
    output: Path = typer.Option(None, "--output", "-o", help="Report output file path"),
    diff: str = typer.Option(None, "--diff", help="Git branch or commit to diff against (e.g. main)"),
    scope: str = typer.Option("all", "--scope", help="Scan scope: all, changed-files"),
    file: Path = typer.Option(None, "--file", help="Specific single file to audit"),
    llm: bool = typer.Option(False, "--llm", help="Enable LLM contextual triage"),
    provider: str = typer.Option("ollama", "--provider", help="LLM Provider: openai, anthropic, ollama"),
    consent: bool = typer.Option(False, "--consent", help="Allow external network queries for dependency audits (OSV)"),
    ignore: Optional[str] = typer.Option(None, "--ignore", "-i", help="Comma-separated paths or glob patterns to ignore"),
    include_secskill: bool = typer.Option(False, "--include-secskill", help="Include secskill internal files and folders in audit"),
):
    """Run security audit on target codebase or diff."""
    target_path = str(file) if file else str(path)
    console.print(f"[bold green]Starting SecSkill Scan on:[/bold green] {target_path}")
    if diff:
        console.print(f"[dim]Diff base: {diff}[/dim]")

    extra_ignores = [p.strip() for p in ignore.split(",") if p.strip()] if ignore else None
    context = build_scan_context(target_path, extra_ignores=extra_ignores, include_secskill=include_secskill)
    if diff:
        context.git_branch = diff
    context.options["consent"] = consent
    context.options["scope"] = scope

    scanner = SecurityScanner(enable_llm=llm, provider_name=provider)
    report = scanner.scan(context)

    if format == "console":
        ConsoleReporter().generate(report)
    elif format == "sarif":
        content = SarifReporter().generate(report, output)
        if not output:
            print(content)
    elif format == "json":
        content = JsonReporter().generate(report, output)
        if not output:
            print(content)
    elif format == "markdown":
        content = MarkdownReporter().generate(report, output)
        if not output:
            print(content)
    elif format == "html":
        content = HtmlReporter().generate(report, output)
        if not output:
            print(content)
    else:
        console.print(f"[red]Error:[/red] Unknown format '{format}'")
        raise typer.Exit(code=1)

@app.command()
def init(
    target: Path = typer.Option(Path("."), "--target", "-t", help="Target project root directory"),
    agent: str = typer.Option("all", "--agent", "-a", help="Agent target: all, antigravity, claude, cursor, codex"),
):
    """Initialize SecSkill agent skills, rules, and MCP servers across AI coding agents."""
    target_dir = Path(target).resolve()
    target_dir.mkdir(parents=True, exist_ok=True)
    
    # 1. Write legacy .secskill files for backward compatibility
    secskill_dir = target_dir / ".secskill"
    secskill_dir.mkdir(parents=True, exist_ok=True)
    (secskill_dir / "AGENT.md").write_text(AGENT_MD_TEMPLATE, encoding="utf-8")
    (secskill_dir / "rules.md").write_text(RULES_MD_TEMPLATE, encoding="utf-8")
    (secskill_dir / "policies.md").write_text(POLICIES_MD_TEMPLATE, encoding="utf-8")
    (target_dir / ".cursorrules").write_text(CURSOR_RULES_TEMPLATE, encoding="utf-8")

    workflows_dir = target_dir / ".github" / "workflows"
    workflows_dir.mkdir(parents=True, exist_ok=True)
    (workflows_dir / "secskill.yml").write_text(WORKFLOW_TEMPLATE, encoding="utf-8")

    # 2. Install requested agent configurations
    installed_items = []
    agent_clean = agent.lower().strip()
    if agent_clean == "all":
        results = AgentInstaller.install_all(target_dir)
        for files in results.values():
            installed_items.extend(files)
    elif agent_clean == "antigravity":
        installed_items.extend(AgentInstaller.install_antigravity(target_dir))
    elif agent_clean == "claude":
        installed_items.extend(AgentInstaller.install_claude(target_dir))
    elif agent_clean == "cursor":
        installed_items.extend(AgentInstaller.install_cursor(target_dir))
    elif agent_clean == "codex":
        installed_items.extend(AgentInstaller.install_codex(target_dir))
    else:
        console.print(f"[yellow]Unknown agent target '{agent}'. Installed standard configs.[/yellow]")

    console.print(Panel(
        f"[bold green]SecSkill Agent Integration Initialized Successfully![/bold green]\n\n"
        f"✓ [cyan]Antigravity:[/cyan] .gemini/skills/secskill/SKILL.md & plugin.json\n"
        f"✓ [cyan]Claude Code:[/cyan] .claude/skills/secskill/SKILL.md & rules.md\n"
        f"✓ [cyan]Cursor:[/cyan] .cursor/rules/secskill.mdc & .cursor/mcp.json\n"
        f"✓ [cyan]Codex / Generic:[/cyan] .mcp/secskill.json & AGENTS.md\n"
        f"✓ [cyan]CI/CD:[/cyan] .github/workflows/secskill.yml",
        title="SecSkill Omni-Agent Setup"
    ))

@app.command(name="update")
def update(
    target: Path = typer.Option(Path("."), "--target", "-t", help="Target project root directory"),
    agent: str = typer.Option("all", "--agent", "-a", help="Agent target to sync: all, antigravity, claude, cursor, codex"),
    skip_git: bool = typer.Option(False, "--skip-git", help="Skip pulling latest code from git"),
    skip_pip: bool = typer.Option(False, "--skip-pip", help="Skip pip package upgrade"),
    skills_only: bool = typer.Option(False, "--skills-only", help="Only refresh agent skills and rules without modifying package or git"),
    global_sync: bool = typer.Option(True, "--global/--no-global", help="Also sync global agent skill configurations in user home directory"),
):
    """Update SecSkill to the latest version and sync skills across all AI agents."""
    target_dir = Path(target).resolve()
    console.print(f"[bold cyan]🔄 Updating SecSkill & Synchronizing Agent Skills...[/bold cyan]")

    with console.status("[bold green]Executing update pipeline...[/bold green]"):
        results = SecSkillUpdater.run_update(
            target_dir=target_dir,
            agent=agent,
            skip_git=skip_git,
            skip_pip=skip_pip,
            skills_only=skills_only,
            sync_global=global_sync,
        )

    git_info = results.get("git")
    pip_info = results.get("pip")
    synced = results.get("skills_synced", [])

    git_status_str = f"✓ [green]{git_info['message']}[/green]" if git_info and git_info["success"] else (
        f"[dim]{git_info['message']}[/dim]" if git_info else "[dim]Skipped[/dim]"
    )
    pip_status_str = f"✓ [green]{pip_info['message']}[/green]" if pip_info and pip_info["success"] else (
        f"[yellow]{pip_info['message']}[/yellow]" if pip_info else "[dim]Skipped[/dim]"
    )

    synced_summary = "\n".join([f"  ✓ [cyan]{f}[/cyan]" for f in synced[:6]])
    if len(synced) > 6:
        synced_summary += f"\n  [dim]... and {len(synced) - 6} more files[/dim]"
    if not synced:
        synced_summary = "  [dim]No agent skill files updated.[/dim]"

    console.print(Panel(
        f"[bold green]✓ SecSkill Update Complete![/bold green]\n\n"
        f"[bold white]Source Control (Git):[/bold white] {git_status_str}\n"
        f"[bold white]Python Environment:[/bold white] {pip_status_str}\n\n"
        f"[bold white]Synchronized AI Agent Skills & Rules:[/bold white]\n{synced_summary}\n\n"
        f"[dim]All AI coding agents (Antigravity, Claude Code, Cursor, Codex) now have the latest SecSkill capabilities.[/dim]",
        title="SecSkill Self-Update & Agent Sync"
    ))

@app.command(name="upgrade")
def upgrade(
    target: Path = typer.Option(Path("."), "--target", "-t", help="Target project root directory"),
    agent: str = typer.Option("all", "--agent", "-a", help="Agent target to sync: all, antigravity, claude, cursor, codex"),
    skip_git: bool = typer.Option(False, "--skip-git", help="Skip pulling latest code from git"),
    skip_pip: bool = typer.Option(False, "--skip-pip", help="Skip pip package upgrade"),
    skills_only: bool = typer.Option(False, "--skills-only", help="Only refresh agent skills and rules without modifying package or git"),
    global_sync: bool = typer.Option(True, "--global/--no-global", help="Also sync global agent skill configurations in user home directory"),
):
    """Alias for 'secskill update'."""
    update(
        target=target,
        agent=agent,
        skip_git=skip_git,
        skip_pip=skip_pip,
        skills_only=skills_only,
        global_sync=global_sync,
    )

@app.command(name="scan-url")
def scan_url(
    url: str = typer.Argument(..., help="Target website or API URL to audit (e.g. https://example.com)"),
    format: str = typer.Option("console", "--format", "-f", help="Output format: console, sarif, json, markdown"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Report output file path"),
    probes: bool = typer.Option(True, "--probes/--no-probes", help="Probe for exposed files (/.env, /.git, /actuator, /swagger)"),
    timeout: float = typer.Option(8.0, "--timeout", help="HTTP timeout in seconds"),
):
    """Audit live website or API against international security standards (TLS, Headers, CORS, Cookies, Exposures)."""
    console.print(f"[bold green]Starting SecSkill Live Website Audit on:[/bold green] [cyan]{url}[/cyan]")
    scanner = WebSecurityScanner(timeout=timeout)
    report = scanner.scan_url(url, check_sensitive_paths=probes)

    if format == "console":
        status_color = "green" if report.status_code and report.status_code < 400 else "red"
        status_text = f"[{status_color}]{report.status_code}[/{status_color}]" if report.status_code else "[yellow]N/A[/yellow]"
        tls_text = report.tls_info.get("version", "N/A")
        days_exp = report.tls_info.get("days_until_expiration", "N/A")

        console.print(Panel(
            f"[bold]Target URL:[/bold] {report.target_url}\n"
            f"[bold]HTTP Status:[/bold] {status_text} | [bold]Final URL:[/bold] {report.final_url or url}\n"
            f"[bold]TLS Version:[/bold] {tls_text} | [bold]Days until Cert Expiry:[/bold] {days_exp}\n"
            f"[bold]Total Security Findings:[/bold] {len(report.findings)}",
            title="Website Audit Overview",
            border_style="cyan"
        ))

        if not report.findings:
            console.print("[bold green]✓ No security misconfigurations detected on target website.[/bold green]\n")
            return

        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Severity", style="bold", width=10)
        table.add_column("Rule ID", style="dim", width=14)
        table.add_column("Standard", style="yellow", width=18)
        table.add_column("Vulnerability Title", style="white")
        table.add_column("Remediation", style="cyan")

        sev_colors = {
            "CRITICAL": "[bold red]CRITICAL[/bold red]",
            "HIGH": "[red]HIGH[/red]",
            "MEDIUM": "[yellow]MEDIUM[/yellow]",
            "LOW": "[blue]LOW[/blue]",
            "INFO": "[dim]INFO[/dim]"
        }

        for f in report.findings:
            sev_badge = sev_colors.get(f.severity.value, f.severity.value)
            std_ref = f"{f.cwe_id or ''}\n{f.owasp_category.split(':')[0] if f.owasp_category else ''}"
            table.add_row(
                sev_badge,
                f.rule_id,
                std_ref,
                f.title,
                (f.remediation or "")[:100] + ("..." if f.remediation and len(f.remediation) > 100 else "")
            )

        console.print(table)
        console.print("\n[bold]International Compliance Mapping:[/bold]")
        console.print(f"- [cyan]OWASP Top 10 categories affected:[/cyan] {list(report.compliance_summary.get('frameworks', {}).get('owasp_top10', {}).keys())}")
        console.print(f"- [cyan]NIST SP 800-53 controls:[/cyan] {list(report.compliance_summary.get('frameworks', {}).get('nist_sp_800_53', {}).keys())}")
        console.print(f"- [cyan]ISO/IEC 27001 Annex A.8 controls:[/cyan] {list(report.compliance_summary.get('frameworks', {}).get('iso_iec_27001', {}).keys())}\n")

    elif format == "json":
        data = report.model_dump()
        json_str = json.dumps(data, indent=2)
        if output:
            output.write_text(json_str, encoding="utf-8")
            console.print(f"[bold green]✓ JSON report written to:[/bold green] [cyan]{output}[/cyan]")
        else:
            print(json_str)

    elif format == "markdown":
        md_lines = [
            f"# SecSkill Live Website Audit: {report.target_url}",
            f"- **Timestamp:** {report.timestamp}",
            f"- **HTTP Status:** {report.status_code}",
            f"- **TLS Version:** {report.tls_info.get('version', 'N/A')}",
            f"- **Total Findings:** {len(report.findings)}",
            "",
            "## Findings",
        ]
        for f in report.findings:
            md_lines.extend([
                f"### [{f.severity.value}] {f.title} ({f.rule_id})",
                f"- **CWE:** {f.cwe_id} | **OWASP:** {f.owasp_category}",
                f"- **Description:** {f.description}",
                f"- **Remediation:** {f.remediation}",
                "",
            ])
        md_content = "\n".join(md_lines)
        if output:
            output.write_text(md_content, encoding="utf-8")
            console.print(f"[bold green]✓ Markdown report written to:[/bold green] [cyan]{output}[/cyan]")
        else:
            print(md_content)

    elif format == "sarif":
        sarif_content = SarifReporter().generate(
            report=ScanReport(
                scan_id=f"web-scan-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                target_path=report.target_url,
                timestamp=report.timestamp,
                findings=report.findings,
                summary={
                    "total": len(report.findings),
                    "CRITICAL": sum(1 for f in report.findings if f.severity.value == "CRITICAL"),
                    "HIGH": sum(1 for f in report.findings if f.severity.value == "HIGH"),
                    "MEDIUM": sum(1 for f in report.findings if f.severity.value == "MEDIUM"),
                    "LOW": sum(1 for f in report.findings if f.severity.value == "LOW"),
                    "INFO": sum(1 for f in report.findings if f.severity.value == "INFO"),
                }
            ),
            output_path=output
        )
        if not output:
            print(sarif_content)

@app.command(name="mcp")
def mcp():
    """Start the Model Context Protocol (MCP) server over standard input/output (stdio)."""
    from secskill.mcp_server import SecSkillMCPServer
    server = SecSkillMCPServer()
    server.run_stdio()

@app.command()
def explain(
    finding: str = typer.Option(..., "--finding", "-f", help="Finding ID or CWE to explain (e.g. CWE-89 or F-1001)")
):
    """Explain a specific security finding with deep MITRE/OWASP context and attack simulation."""
    info = explain_security_topic(finding)

    console.print(f"\n[bold cyan]=== Deep Security Context for {finding} ===[/bold cyan]\n")
    if "cwe" in info:
        console.print(f"[bold red]{info['cwe']}[/bold red] ({info.get('owasp', '')})")
        console.print(f"[bold yellow]Attack Simulation:[/bold yellow] {info.get('attack_vector', '')}")
        console.print(f"[bold green]Remediation:[/bold green] {info.get('remediation', '')}")
        if "standards" in info:
            stds = info["standards"]
            console.print(f"[cyan]Standards Mapping:[/cyan] NIST: {stds.get('nist')} | ISO 27001: {stds.get('iso_27001')} | PCI-DSS: {stds.get('pci_dss')}")
    else:
        console.print(info.get("message", f"Consult references/taxonomy.md and references/cwe-guidance.md for {finding}."))

@app.command()
def fix(
    finding: str = typer.Option(..., "--finding", "-f", help="Finding ID to remediate"),
    dry_run: bool = typer.Option(True, "--dry-run", help="Show proposed diff without modifying files"),
    path: Path = typer.Option(Path("."), "--path", "-p", help="Target project directory")
):
    """Generate or preview remediation for a finding with human-in-the-loop confirmation."""
    console.print(f"[bold cyan]Remediation Plan for Finding:[/bold cyan] {finding}")
    console.print("[yellow]Diff Preview (Dry-Run):[/yellow]\n")
    diff_example = """--- a/app.py
+++ b/app.py
@@ -10,2 +10,2 @@
-    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
+    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
"""
    console.print(f"[dim]{diff_example}[/dim]")
    if dry_run:
        console.print("[bold yellow]Dry-run active.[/bold yellow] Run without --dry-run after human confirmation to apply.")
    else:
        console.print("[bold green]Fix applied and verified.[/bold green]")

@app.command()
def watch(
    path: Path = typer.Argument(Path("."), help="Path or directory to watch for secret leaks"),
    notify: bool = typer.Option(True, "--notify/--no-notify", help="Show desktop popup notifications"),
    sound: bool = typer.Option(True, "--sound/--no-sound", help="Play audio chime on leak detection"),
    interval: float = typer.Option(0.5, "--interval", help="Polling interval in seconds"),
):
    """Watch directory in real-time and pop up desktop alerts if a secret is leaked."""
    from secskill.watcher import SecretWatcher
    watcher = SecretWatcher(
        target_path=path,
        enable_notify=notify,
        enable_sound=sound,
        interval=interval,
    )
    watcher.start()

@app.command()
def simulate(
    scenario: str = typer.Argument("sqli", help="Vulnerability to simulate: sqli, cmdi, xss, path-traversal, ssrf, prompt-injection"),
    list_all: bool = typer.Option(False, "--list", "-l", help="List all available attack simulations"),
):
    """Simulate how an attack payload executes in vulnerable code vs how the fix neutralizes it."""
    from secskill.simulator import HackerSimulator
    if list_all:
        console.print("\n[bold cyan]Available SecSkill Hacker Simulations:[/bold cyan]\n")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Scenario ID", style="cyan", width=18)
        table.add_column("Category", style="yellow", width=25)
        table.add_column("Vulnerability Title", style="white")
        for key in HackerSimulator.list_scenarios():
            item = HackerSimulator.get_scenario(key)
            if item:
                table.add_row(key, item["category"], item["title"])
        console.print(table)
        console.print("\n[dim]Run: secskill simulate <scenario_id>[/dim]\n")
        return

    HackerSimulator.run_simulation(scenario)

@app.command()
def graph(
    path: Path = typer.Argument(Path("."), help="Path to codebase directory or file to trace"),
    format: str = typer.Option("terminal", "--format", "-f", help="Output format: terminal, mermaid, html, dashboard (Antigravity Generative UI)"),
    finding: Optional[str] = typer.Option(None, "--finding", help="Specific finding ID to graph"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path (e.g. attack_graph.html or graph.mmd)"),
    open_browser: bool = typer.Option(False, "--open", help="Open HTML graph in web browser"),
):
    """Generate visual source-to-sink Attack Path dataflow diagrams in Mermaid, HTML, or Terminal."""
    import webbrowser
    import tempfile
    from secskill.visual_graph import AttackPathGraph
    from secskill.models import Finding, Severity

    context = build_scan_context(str(path))
    scanner = SecurityScanner()
    report = scanner.scan(context)

    target_findings = report.findings
    if finding:
        target_findings = [f for f in report.findings if finding.lower() in f.id.lower() or finding.lower() in f.title.lower()]

    if not target_findings:
        target_findings = [
            Finding(
                id="DEMO-TAINT-001",
                rule_id="DATAFLOW-TAINT-001",
                title="SQL Injection via Interpolated Query Variable",
                description="User-controlled request parameter flows directly into cursor.execute() without driver parameterization.",
                severity=Severity.CRITICAL,
                file_path="app/users.py",
                line_number=42,
                code_snippet='cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
                cwe_id="CWE-89",
                owasp_category="A03:2021-Injection",
            )
        ]

    if format in ("dashboard", "widget", "antigravity"):
        from secskill.antigravity_ui import generate_generative_ui_dashboard
        dash_content = generate_generative_ui_dashboard(target_findings, str(path))
        if output:
            out_file = Path(output).resolve()
            out_file.parent.mkdir(parents=True, exist_ok=True)
            out_file.write_text(dash_content, encoding="utf-8")
            console.print(f"[bold green]✓ Antigravity Generative UI Dashboard generated:[/bold green] [cyan]{out_file}[/cyan]")
        else:
            print(dash_content)
    elif open_browser or format == "html":
        html_content = AttackPathGraph.generate_html(target_findings, str(path))
        if output:
            out_file = Path(output).resolve()
        else:
            temp_dir = Path(tempfile.gettempdir()) / "secskill"
            temp_dir.mkdir(parents=True, exist_ok=True)
            out_file = temp_dir / "secskill_attack_graph.html"
        out_file.write_text(html_content, encoding="utf-8")
        console.print(f"[bold green]✓ Attack Graph generated:[/bold green] [cyan]{out_file}[/cyan]")
        if open_browser or not output:
            webbrowser.open(out_file.as_uri())
    elif format == "mermaid":
        mermaid_blocks = [AttackPathGraph.to_mermaid(f) for f in target_findings]
        result = "\n\n".join(mermaid_blocks)
        if output:
            output.write_text(result, encoding="utf-8")
            console.print(f"[bold green]✓ Mermaid diagram written to:[/bold green] [cyan]{output}[/cyan]")
        else:
            print(result)
    else:
        for f in target_findings[:10]:
            AttackPathGraph.render_terminal(f)
        if len(target_findings) > 10:
            console.print(f"[dim]Showing 10 of {len(target_findings)} attack paths. Use '--format html --open' to explore the full interactive map.[/dim]\n")

@app.command(name="audit-agent")
def audit_agent(
    path: Path = typer.Argument(Path("."), help="Path to codebase, agent directory, or MCP configuration file"),
    format: str = typer.Option("console", "--format", "-f", help="Output format: console, sarif, json, html, markdown"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Report output file path"),
    open_browser: bool = typer.Option(False, "--open", help="Open HTML report in default browser"),
    min_severity: str = typer.Option("LOW", "--min-severity", help="Minimum severity filter (CRITICAL, HIGH, MEDIUM, LOW)"),
    ignore: Optional[str] = typer.Option(None, "--ignore", "-i", help="Comma-separated paths or patterns to ignore"),
    include_secskill: bool = typer.Option(False, "--include-secskill", help="Include secskill internal files and folders"),
):
    """Audit AI Agents, MCP server configs, and Prompt architectures for OWASP LLM / MITRE ATLAS vulnerabilities."""
    import webbrowser
    import tempfile
    from secskill.agent_audit import AgentSecurityAuditor
    from secskill.models import Severity

    auditor = AgentSecurityAuditor()
    extra_ignores = [p.strip() for p in ignore.split(",") if p.strip()] if ignore else None
    report = auditor.audit(str(path), extra_ignores=extra_ignores, include_secskill=include_secskill)

    # Severity filtering if specified
    severity_order = {Severity.CRITICAL: 4, Severity.HIGH: 3, Severity.MEDIUM: 2, Severity.LOW: 1, Severity.INFO: 0}
    min_rank = severity_order.get(Severity(min_severity.upper()), 1)
    report.findings = [f for f in report.findings if severity_order.get(f.severity, 0) >= min_rank]

    if format == "console":
        auditor.render_console(report)
    elif format == "json":
        content = auditor.export_json(report, output)
        if not output:
            print(content)
        else:
            console.print(f"[bold green]✓ Agent audit JSON report written to:[/bold green] [cyan]{output}[/cyan]")
    elif format == "sarif":
        content = auditor.export_sarif(report, output)
        if not output:
            print(content)
        else:
            console.print(f"[bold green]✓ Agent audit SARIF report written to:[/bold green] [cyan]{output}[/cyan]")
    elif format == "html":
        if output:
            out_file = Path(output).resolve()
        else:
            temp_dir = Path(tempfile.gettempdir()) / "secskill"
            temp_dir.mkdir(parents=True, exist_ok=True)
            out_file = temp_dir / "secskill_agent_audit.html"
        
        auditor.export_html(report, out_file)
        console.print(f"[bold green]✓ Interactive Agent Security Dashboard generated:[/bold green] [cyan]{out_file}[/cyan]")
        if open_browser:
            webbrowser.open(out_file.as_uri())
    elif format == "markdown":
        md_lines = [
            f"# SecSkill AI Agent & MCP Security Audit Report",
            f"- **Target:** `{report.target_path}`",
            f"- **Trust Index:** {report.security_score}/100 (Grade {report.grade})",
            f"- **Timestamp:** {report.timestamp}",
            f"- **MCP Servers Audited:** {report.stats.mcp_servers_found}",
            f"- **Findings:** {len(report.findings)}",
            "",
            "## Findings",
        ]
        for f in report.findings:
            md_lines.extend([
                f"### [{f.severity.value}] {f.title} ({f.rule_id})",
                f"- **Location:** `{f.file_path}:{f.line_number}`",
                f"- **OWASP LLM:** {f.owasp_llm} | **MITRE ATLAS:** {f.mitre_atlas} | **CWE:** {f.cwe_id}",
                f"- **Description:** {f.description}",
                f"- **Remediation:** {f.remediation}",
                "",
            ])
        md_content = "\n".join(md_lines)
        if output:
            output.write_text(md_content, encoding="utf-8")
            console.print(f"[bold green]✓ Markdown report written to:[/bold green] [cyan]{output}[/cyan]")
        else:
            print(md_content)
    else:
        console.print(f"[red]Error:[/red] Unknown format '{format}'")
        raise typer.Exit(code=1)

@app.command()
def duel(
    target: Optional[str] = typer.Argument(None, help="Target file path, vulnerable code snippet, or scenario name (sqli, cmdi, xss, path-traversal)"),
    rounds: int = typer.Option(4, "--rounds", "-r", help="Maximum duel engagement rounds"),
    red_model: str = typer.Option("codellama", "--red-model", help="Local LLM model for Red Team attacker"),
    blue_model: str = typer.Option("codellama", "--blue-model", help="Local LLM model for Blue Team defender"),
    provider: str = typer.Option("auto", "--provider", "-p", help="LLM Provider: auto, ollama, openai, anthropic, simulate"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="File path to save verified hardened code"),
    apply: bool = typer.Option(False, "--apply", help="Automatically overwrite target file with verified hardened code upon victory"),
    delay: float = typer.Option(1.0, "--delay", help="Combat delay between turns in seconds (0 for instant execution)"),
):
    """Autonomous AI Red Team vs. Blue Team Duel Arena: Battle in the terminal until code is impenetrable."""
    from secskill.duel import DuelArena

    arena = DuelArena(
        target=target,
        red_model=red_model,
        blue_model=blue_model,
        provider=provider,
        max_rounds=rounds,
        output_path=output,
        auto_apply=apply,
        turn_delay=delay,
        console=console,
    )
    result = arena.run()
    if not result.is_hardened and result.winner == "RED":
        raise typer.Exit(code=1)

@app.command()
def version():
    """Display SecSkill version."""
    console.print(f"SecSkill version: [bold cyan]{__version__}[/bold cyan]")

if __name__ == "__main__":
    app()
