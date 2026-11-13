"""Attack Path and Dataflow Visual Graph Generator (Mermaid, SVG, HTML & Terminal)."""
import html as html_lib
from typing import List, Dict, Any
from rich.console import Console
from rich.panel import Panel

from secskill.models import Finding

console = Console()

class AttackPathGraph:
    """Transforms security findings into visual source-to-sink dataflow graphs."""

    @staticmethod
    def infer_attack_path(finding: Finding) -> Dict[str, Any]:
        """Infer structured source-to-sink steps from a finding."""
        cwe = (finding.cwe_id or "").upper()
        title = finding.title
        file_path = finding.file_path
        line = finding.line_number
        snippet = finding.code_snippet or ""

        if "89" in cwe or "SQL" in title.upper():
            return {
                "source": "🌐 HTTP Request (query/body parameter)",
                "source_type": "Untrusted User Input",
                "route": f"⚙️ Endpoint Handler ({file_path})",
                "flaw": "⚠️ String Interpolation / Missing Parameter Binding",
                "sink": f"💥 cursor.execute() ({file_path}:{line})",
                "impact": "Database Records Exfiltrated / Auth Bypass",
            }
        elif "78" in cwe or "COMMAND" in title.upper():
            return {
                "source": "🌐 User CLI / API Argument",
                "source_type": "Untrusted Parameter",
                "route": f"⚙️ System Call Wrapper ({file_path})",
                "flaw": "⚠️ shell=True with Unescaped Metacharacters",
                "sink": f"💥 OS Command Execution ({file_path}:{line})",
                "impact": "Arbitrary Remote Command Execution (RCE)",
            }
        elif "79" in cwe or "XSS" in title.upper():
            return {
                "source": "🌐 URL Query / Form Input",
                "source_type": "Unsanitized String",
                "route": f"⚙️ View Template / Handler ({file_path})",
                "flaw": "⚠️ Missing HTML Entity Escaping (DOMPurify/escapeHtml)",
                "sink": f"💥 Direct HTML Response ({file_path}:{line})",
                "impact": "Client Browser Session Token Theft (XSS)",
            }
        elif "22" in cwe or "TRAVERSAL" in title.upper() or "PATH" in title.upper():
            return {
                "source": "🌐 File Download Request Parameter",
                "source_type": "Relative Path with '../'",
                "route": f"⚙️ File Loader ({file_path})",
                "flaw": "⚠️ Missing Canonical Path Validation (resolve())",
                "sink": f"💥 open() File System Sink ({file_path}:{line})",
                "impact": "Arbitrary File Disclosure (/etc/passwd, secrets)",
            }
        elif "798" in cwe or "SECRET" in title.upper():
            return {
                "source": f"🔑 Hardcoded Credential in Code ({file_path}:{line})",
                "source_type": "Static Secret in Git History",
                "route": "⚙️ Module Initialization",
                "flaw": "⚠️ Token Hardcoded Instead of Vault / Environment Variable",
                "sink": "💥 Cloud / Third-Party Provider API",
                "impact": "Full Unauthorized Cloud Account Takeover",
            }
        elif "74" in cwe or "PROMPT" in title.upper() or "LLM" in title.upper():
            return {
                "source": "🌐 User Chat / Feedback String",
                "source_type": "Untrusted Prompt Injection",
                "route": f"⚙️ Agent Prompt Builder ({file_path})",
                "flaw": "⚠️ Prompt Concatenation without Role / XML Tagging",
                "sink": f"💥 llm.generate() / Tool Sink ({file_path}:{line})",
                "impact": "Agent Instruction Hijack & Unauthorized Tool Calling",
            }
        else:
            return {
                "source": "🌐 External Untrusted Input",
                "source_type": "User-Controlled Data",
                "route": f"⚙️ Application Logic ({file_path})",
                "flaw": f"⚠️ {finding.title}",
                "sink": f"💥 Sensitive Execution Sink ({file_path}:{line})",
                "impact": "Potential Confidentiality or Integrity Breach",
            }

    @classmethod
    def to_mermaid(cls, finding: Finding) -> str:
        """Convert a finding into a GitHub-ready Mermaid flowchart."""
        path_data = cls.infer_attack_path(finding)
        
        # Safe IDs without spaces
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

    @classmethod
    def render_terminal(cls, finding: Finding) -> None:
        """Render a colorful ASCII/Unicode pipeline in the console."""
        path_data = cls.infer_attack_path(finding)
        
        console.print()
        console.print(
            Panel(
                f"[bold red]Attack Path Dataflow:[/bold red] [white]{finding.title}[/white]\n"
                f"[dim]CWE: {finding.cwe_id or 'N/A'} | Location: {finding.file_path}:{finding.line_number}[/dim]",
                title="🗺️ SecSkill Visual Dataflow Graph",
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
            console.print(f"  {step_title}")
            console.print(f"    ┌─► [bold white]{node_name}[/bold white]")
            console.print(f"    │   {meta}")
            if step_title != flow_steps[-1][0]:
                console.print("    ▼")

        console.print()

    @classmethod
    def generate_html(cls, findings: List[Finding], target_path: str = ".") -> str:
        """Generate a standalone, interactive HTML attack graph visualizer."""
        graphs_html = []
        for idx, f in enumerate(findings):
            path_data = cls.infer_attack_path(f)
            sev = f.severity.value.lower()
            snippet = html_lib.escape(f.code_snippet or "No snippet")
            cwe = html_lib.escape(f.cwe_id or "CWE-General")

            graphs_html.append(f"""
            <div class="graph-card">
                <div class="graph-header">
                    <div class="title-wrap">
                        <span class="badge {sev}">{f.severity.value}</span>
                        <h3>{html_lib.escape(f.title)}</h3>
                    </div>
                    <span class="loc-tag">📁 {html_lib.escape(f.file_path)}:<strong>{f.line_number}</strong></span>
                </div>
                
                <div class="pipeline">
                    <div class="pipe-node node-source">
                        <div class="node-badge">SOURCE</div>
                        <div class="node-icon">🌐</div>
                        <div class="node-label">{html_lib.escape(path_data['source'])}</div>
                        <div class="node-meta">{html_lib.escape(path_data['source_type'])}</div>
                    </div>
                    
                    <div class="pipe-arrow">➔</div>

                    <div class="pipe-node node-route">
                        <div class="node-badge">ROUTING</div>
                        <div class="node-icon">⚙️</div>
                        <div class="node-label">{html_lib.escape(path_data['route'])}</div>
                        <div class="node-meta">Application Handler</div>
                    </div>

                    <div class="pipe-arrow arrow-warn">➔</div>

                    <div class="pipe-node node-flaw">
                        <div class="node-badge badge-flaw">NO SANITIZER</div>
                        <div class="node-icon">⚠️</div>
                        <div class="node-label">{html_lib.escape(path_data['flaw'])}</div>
                        <div class="node-meta">Direct Concatenation</div>
                    </div>

                    <div class="pipe-arrow arrow-danger">➔</div>

                    <div class="pipe-node node-sink">
                        <div class="node-badge badge-danger">SINK</div>
                        <div class="node-icon">💥</div>
                        <div class="node-label">{html_lib.escape(path_data['sink'])}</div>
                        <div class="node-meta">Sensitive Execution</div>
                    </div>

                    <div class="pipe-arrow arrow-danger">➔</div>

                    <div class="pipe-node node-impact">
                        <div class="node-badge badge-impact">IMPACT</div>
                        <div class="node-icon">☠️</div>
                        <div class="node-label">{html_lib.escape(path_data['impact'])}</div>
                        <div class="node-meta">Security Breach</div>
                    </div>
                </div>

                <div class="snippet-bar">
                    <code>{snippet}</code>
                </div>
            </div>
            """)

        graphs_rendered = "\n".join(graphs_html) if graphs_html else """
        <div class="empty-state">
            <h2>🎉 No High or Critical Attack Paths Detected</h2>
            <p>Codebase entry points and dataflow sinks are properly sanitized.</p>
        </div>
        """

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecSkill Attack Path Visualizer</title>
    <style>
        :root {{
            --bg-base: #0a0e17;
            --bg-card: #111827;
            --border: #1e293b;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --danger: #ef4444;
            --warning: #f97316;
            --cyan: #06b6d4;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg-base);
            color: var(--text-main);
            padding: 2.5rem 2rem;
            min-height: 100vh;
        }}
        .container {{ max-width: 1300px; margin: 0 auto; }}
        header {{
            margin-bottom: 2.5rem;
            border-bottom: 1px solid var(--border);
            padding-bottom: 1.5rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
        }}
        .header-title h1 {{
            font-size: 1.8rem;
            background: linear-gradient(135deg, #f87171 0%, #fb923c 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .header-title p {{ color: var(--text-muted); font-size: 0.9rem; margin-top: 0.2rem; }}
        
        .graph-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 1.75rem;
            margin-bottom: 2rem;
            box-shadow: 0 10px 25px -5px rgba(0,0,0,0.4);
            border-left: 6px solid var(--danger);
        }}
        .graph-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
            flex-wrap: wrap;
            gap: 0.75rem;
        }}
        .title-wrap {{ display: flex; align-items: center; gap: 0.75rem; }}
        .title-wrap h3 {{ font-size: 1.15rem; font-weight: 700; }}
        .badge {{ padding: 3px 8px; border-radius: 6px; font-weight: 800; font-size: 0.75rem; }}
        .badge.critical {{ background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid #ef4444; }}
        .badge.high {{ background: rgba(249, 115, 22, 0.2); color: #f97316; border: 1px solid #f97316; }}
        .loc-tag {{ font-size: 0.85rem; color: var(--text-muted); background: #0f172a; padding: 4px 10px; border-radius: 6px; border: 1px solid var(--border); }}

        /* Interactive Pipeline Visual */
        .pipeline {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 0.5rem;
            overflow-x: auto;
            padding: 1rem 0;
            margin-bottom: 1.5rem;
        }}
        .pipe-node {{
            background: #0f172a;
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1rem;
            min-width: 190px;
            max-width: 210px;
            text-align: center;
            position: relative;
            box-shadow: 0 4px 12px rgba(0,0,0,0.25);
            transition: transform 0.2s, border-color 0.2s;
        }}
        .pipe-node:hover {{ transform: translateY(-4px); border-color: var(--cyan); }}
        .node-badge {{
            position: absolute;
            top: -10px;
            left: 50%;
            transform: translateX(-50%);
            background: #1e293b;
            color: var(--text-muted);
            font-size: 0.65rem;
            font-weight: 800;
            padding: 2px 8px;
            border-radius: 9999px;
            border: 1px solid var(--border);
            letter-spacing: 0.05em;
        }}
        .node-icon {{ font-size: 1.8rem; margin: 0.4rem 0 0.2rem 0; }}
        .node-label {{ font-size: 0.85rem; font-weight: 700; color: #f1f5f9; line-height: 1.25; margin-bottom: 0.25rem; }}
        .node-meta {{ font-size: 0.72rem; color: var(--text-muted); }}

        .node-source {{ border-top: 3px solid #38bdf8; }}
        .node-flaw {{ border-top: 3px solid var(--warning); background: rgba(249, 115, 22, 0.05); }}
        .badge-flaw {{ background: #f97316 !important; color: black !important; }}
        .node-sink {{ border-top: 3px solid var(--danger); background: rgba(239, 68, 68, 0.08); }}
        .badge-danger {{ background: #ef4444 !important; color: white !important; }}
        .node-impact {{ border-top: 3px solid #b91c1c; background: rgba(185, 28, 28, 0.12); }}
        .badge-impact {{ background: #991b1b !important; color: white !important; }}

        .pipe-arrow {{
            color: #475569;
            font-size: 1.4rem;
            font-weight: 900;
        }}
        .arrow-warn {{ color: var(--warning); }}
        .arrow-danger {{ color: var(--danger); animation: pulse 1.5s infinite; }}

        @keyframes pulse {{
            0%, 100% {{ opacity: 1; transform: scale(1); }}
            50% {{ opacity: 0.6; transform: scale(1.15); }}
        }}

        .snippet-bar {{
            background: #090d16;
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 0.75rem 1rem;
            font-family: monospace;
            font-size: 0.85rem;
            color: #e2e8f0;
            overflow-x: auto;
        }}

        .empty-state {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 3rem;
            text-align: center;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="header-title">
                <h1>🗺️ SecSkill Attack Path Visualizer</h1>
                <p>Untrusted Source ➔ Unsanitized Flow ➔ Sensitive Execution Sink</p>
            </div>
            <div>
                <span class="loc-tag">Scanned Scope: <strong>{html_lib.escape(target_path)}</strong></span>
            </div>
        </header>

        {graphs_rendered}
    </div>
</body>
</html>"""

