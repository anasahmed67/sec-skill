"""Terminal Unicode and Markdown Mermaid diagram presenters."""
from typing import Optional
from rich.console import Console
from rich.panel import Panel
from secskill.models import Finding
from secskill.graph.inference import infer_attack_path

_default_console: Optional[Console] = None

def _get_console(console: Optional[Console] = None) -> Console:
    global _default_console
    if console is not None:
        return console
    if _default_console is None:
        _default_console = Console()
    return _default_console

def render_terminal_pipeline(finding: Finding, console: Optional[Console] = None) -> None:
    """Render a clean Unicode pipeline in the console with optional injected Console."""
    c = _get_console(console)
    path_data = infer_attack_path(finding)

    c.print()
    c.print(
        Panel(
            f"[bold red]Attack Path Dataflow:[/bold red] [white]{finding.title}[/white]\n"
            f"[dim]CWE: {finding.cwe_id or 'N/A'} | Location: {finding.file_path}:{finding.line_number}[/dim]",
            title="SecSkill Visual Dataflow Graph",
            border_style="red"
        )
    )

    flow_steps = [
        ("[bold red]1. Entrypoint (Source):[/bold red]", path_data["source"], "[dim]Data type: " + path_data["source_type"] + "[/dim]"),
        ("[bold cyan]2. Processing (Route):[/bold cyan]", path_data["route"], "[dim]Request routing & parameter parsing[/dim]"),
        ("[bold yellow]3. Security Vulnerability:[/bold yellow]", path_data["flaw"], "[red]Validation Missing![/red]"),
        ("[bold bright_red]4. Execution (Sink):[/bold bright_red]", path_data["sink"], f"[dim]Code: {finding.code_snippet or ''}[/dim]"),
        ("[bold magenta]5. Impact (Blast Radius):[/bold magenta]", path_data["impact"], "[bold red]Exploited Outcome[/bold red]")
    ]

    for step_title, node_name, meta in flow_steps:
        c.print(f"  {step_title}")
        c.print(f"    ┌─► [bold white]{node_name}[/bold white]")
        c.print(f"    │   {meta}")
        if step_title != flow_steps[-1][0]:
            c.print("    ▼")

    c.print()

def to_mermaid_flowchart(finding: Finding) -> str:
    """Convert a finding into a GitHub-ready Mermaid flowchart."""
    path_data = infer_attack_path(finding)

    return f"""```mermaid
flowchart LR
    A["{path_data['source']}"] -->|"untrusted payload"| B["{path_data['route']}"]
    B -->|"{path_data['flaw']}"| C["{path_data['sink']}"]
    C -->|"blast radius"| D[("{path_data['impact']}")]

    style A fill:#ef4444,stroke:#fff,stroke-width:2px,color:#fff
    style B fill:#1e293b,stroke:#38bdf8,stroke-width:2px,color:#fff
    style C fill:#dc2626,stroke:#fff,stroke-width:2px,color:#fff
    style D fill:#7f1d1d,stroke:#fff,stroke-width:2px,color:#fff
```"""

