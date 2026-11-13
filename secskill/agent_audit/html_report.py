"""Interactive Cyberpunk HTML Report Generator for AI Agent & MCP Security Audits."""
import html as html_lib
from pathlib import Path
from typing import Optional
from secskill.agent_audit.models import AgentAuditReport, Severity

class AgentAuditHtmlReporter:
    """Generates an interactive, dark-mode cybersecurity dashboard for Agent & MCP scans."""

    @classmethod
    def generate(cls, report: AgentAuditReport, output_path: Optional[Path] = None) -> str:
        score = report.security_score
        grade = report.grade

        if score >= 90:
            score_color = "#00ff88"
            score_glow = "0 0 25px rgba(0,255,136,0.5)"
        elif score >= 75:
            score_color = "#60a5fa"
            score_glow = "0 0 25px rgba(96,165,250,0.5)"
        elif score >= 50:
            score_color = "#fbbf24"
            score_glow = "0 0 25px rgba(251,191,36,0.5)"
        else:
            score_color = "#f43f5e"
            score_glow = "0 0 25px rgba(244,63,94,0.6)"

        # Build MCP Server Rows
        mcp_rows_html = []
        for s in report.mcp_servers:
            shell_badge = '<span class="badge badge-crit">❌ EXPOSED</span>' if s.has_shell_access else '<span class="badge badge-safe">✅ RESTRICTED</span>'
            root_badge = '<span class="badge badge-high">⚠️ ROOT / HOME</span>' if s.has_filesystem_root else '<span class="badge badge-safe">✅ SCOPED</span>'
            env_badge = '<span class="badge badge-high">❌ EXPOSED SECRET</span>' if s.has_raw_env_secrets else '<span class="badge badge-safe">✅ SECURE</span>'
            pin_badge = '<span class="badge badge-safe">✅ PINNED</span>' if s.is_pinned else '<span class="badge badge-med">⚠️ UNPINNED</span>'

            risk_class = "crit" if s.risk_level == Severity.CRITICAL else ("high" if s.risk_level == Severity.HIGH else ("med" if s.risk_level == Severity.MEDIUM else "safe"))
            mcp_rows_html.append(f"""
            <tr>
                <td><strong>{html_lib.escape(s.server_name)}</strong></td>
                <td><code>{html_lib.escape(s.command)}</code></td>
                <td>{shell_badge}</td>
                <td>{root_badge}</td>
                <td>{env_badge}</td>
                <td>{pin_badge}</td>
                <td><span class="badge badge-{risk_class}">{s.risk_level.value}</span></td>
            </tr>
            """)
        mcp_table_body = "\n".join(mcp_rows_html) if mcp_rows_html else "<tr><td colspan='7' style='text-align:center; color:#6b7280;'>No standalone MCP servers detected in target scope.</td></tr>"

        # Build Finding Cards
        findings_html = []
        for f in report.findings:
            sev_class = f.severity.value.lower()
            code_block = ""
            if f.code_snippet:
                code_block = f"""
                <div class="code-box">
                    <div class="code-header"><span>{html_lib.escape(f.file_path)}:{f.line_number}</span></div>
                    <pre><code>{html_lib.escape(f.code_snippet)}</code></pre>
                </div>
                """

            fix_block = ""
            if f.suggested_fix:
                fix_block = f"""
                <div class="fix-box">
                    <div class="fix-header">💡 Proposed Remediation Patch:</div>
                    <pre><code>{html_lib.escape(f.suggested_fix)}</code></pre>
                </div>
                """

            findings_html.append(f"""
            <div class="card finding-card border-{sev_class}" data-severity="{sev_class}" data-category="{html_lib.escape(f.category.value)}">
                <div class="card-header">
                    <div>
                        <span class="badge badge-{sev_class}">{f.severity.value}</span>
                        <span class="category-tag">{html_lib.escape(f.category.value)}</span>
                        <span class="cwe-tag">{html_lib.escape(f.cwe_id)}</span>
                    </div>
                    <span class="rule-id">{html_lib.escape(f.rule_id)}</span>
                </div>
                <h3 class="finding-title">{html_lib.escape(f.title)}</h3>
                <p class="finding-desc">{html_lib.escape(f.description)}</p>
                <div class="tag-row">
                    <span class="owasp-tag">🛡️ {html_lib.escape(f.owasp_llm)}</span>
                    <span class="mitre-tag">🗺️ {html_lib.escape(f.mitre_atlas)}</span>
                </div>
                {code_block}
                <div class="remediation-text"><strong>Remediation:</strong> {html_lib.escape(f.remediation)}</div>
                {fix_block}
            </div>
            """)
        findings_rendered = "\n".join(findings_html) if findings_html else "<div class='card' style='text-align:center; padding:3rem; color:#00ff88;'>🛡️ No agent or MCP vulnerabilities detected! Excellent posture.</div>"

        # OWASP Summary Cards
        owasp_items = []
        for owasp_k, count in report.owasp_llm_summary.items():
            owasp_items.append(f"""
            <div class="owasp-pill">
                <span class="owasp-count">{count}</span>
                <span class="owasp-label">{html_lib.escape(owasp_k)}</span>
            </div>
            """)
        owasp_pills_html = "\n".join(owasp_items) if owasp_items else "<div style='color:#6b7280;'>Zero OWASP LLM violations.</div>"

        html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecSkill AI Agent &amp; MCP Security Audit Report</title>
    <style>
        :root {{
            --bg-primary: #0a0e17;
            --bg-secondary: #111827;
            --bg-card: #161f30;
            --border-color: #1f293d;
            --text-primary: #f3f4f6;
            --text-secondary: #9ca3af;
            --accent-green: #00ff88;
            --accent-blue: #38bdf8;
            --accent-yellow: #fbbf24;
            --accent-red: #f43f5e;
            --accent-purple: #a855f7;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            background-color: var(--bg-primary);
            color: var(--text-primary);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.5;
            padding: 2rem 1.5rem;
        }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        
        /* Header */
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 2rem;
            border-bottom: 1px solid var(--border-color);
            margin-bottom: 2rem;
            flex-wrap: wrap;
            gap: 1.5rem;
        }}
        .brand {{ display: flex; align-items: center; gap: 1rem; }}
        .brand-text h1 {{ font-size: 1.75rem; font-weight: 800; letter-spacing: -0.5px; }}
        .brand-text h1 span {{ color: var(--accent-green); }}
        .brand-text p {{ color: var(--text-secondary); font-size: 0.9rem; }}

        /* Score Gauge */
        .score-box {{
            display: flex;
            align-items: center;
            gap: 1.5rem;
            background: var(--bg-secondary);
            padding: 1rem 1.5rem;
            border-radius: 12px;
            border: 1px solid var(--border-color);
            box-shadow: {score_glow};
        }}
        .score-circle {{
            font-size: 2.5rem;
            font-weight: 900;
            color: {score_color};
            line-height: 1;
        }}
        .score-meta {{ font-size: 0.85rem; color: var(--text-secondary); }}
        .grade-badge {{
            display: inline-block;
            background: rgba(255,255,255,0.08);
            border: 1px solid {score_color};
            color: {score_color};
            padding: 0.2rem 0.6rem;
            border-radius: 6px;
            font-weight: 700;
            font-size: 1.1rem;
            margin-top: 0.25rem;
        }}

        /* Metrics Row */
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        .metric-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 1.25rem;
            text-align: center;
        }}
        .metric-val {{ font-size: 2rem; font-weight: 800; color: var(--text-primary); }}
        .metric-label {{ color: var(--text-secondary); font-size: 0.85rem; margin-top: 0.25rem; }}

        /* Section Titles */
        .section-title {{
            font-size: 1.3rem;
            font-weight: 700;
            margin: 2rem 0 1rem 0;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}

        /* MCP Table */
        .table-wrap {{
            overflow-x: auto;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            margin-bottom: 2.5rem;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9rem;
            text-align: left;
        }}
        th, td {{
            padding: 0.85rem 1rem;
            border-bottom: 1px solid var(--border-color);
        }}
        th {{
            background: rgba(255,255,255,0.02);
            color: var(--text-secondary);
            font-weight: 600;
        }}
        code {{
            background: rgba(255,255,255,0.05);
            padding: 0.15rem 0.4rem;
            border-radius: 4px;
            font-family: ui-monospace, Menlo, Consolas, monospace;
            font-size: 0.85rem;
            color: var(--accent-blue);
        }}

        /* Badges */
        .badge {{
            display: inline-block;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
        }}
        .badge-crit {{ background: rgba(244,63,94,0.2); color: var(--accent-red); border: 1px solid var(--accent-red); }}
        .badge-high {{ background: rgba(251,191,36,0.2); color: var(--accent-yellow); border: 1px solid var(--accent-yellow); }}
        .badge-med {{ background: rgba(56,189,248,0.2); color: var(--accent-blue); border: 1px solid var(--accent-blue); }}
        .badge-low, .badge-safe {{ background: rgba(0,255,136,0.2); color: var(--accent-green); border: 1px solid var(--accent-green); }}

        /* OWASP Pills */
        .owasp-flex {{ display: flex; flex-wrap: wrap; gap: 0.75rem; margin-bottom: 2rem; }}
        .owasp-pill {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            padding: 0.5rem 0.85rem;
            border-radius: 8px;
            display: flex;
            align-items: center;
            gap: 0.6rem;
            font-size: 0.85rem;
        }}
        .owasp-count {{
            background: rgba(244,63,94,0.25);
            color: var(--accent-red);
            font-weight: 800;
            padding: 0.1rem 0.45rem;
            border-radius: 6px;
        }}

        /* Findings Explorer */
        .filter-bar {{
            display: flex;
            gap: 0.5rem;
            margin-bottom: 1.5rem;
            flex-wrap: wrap;
        }}
        .filter-btn {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            color: var(--text-secondary);
            padding: 0.4rem 0.85rem;
            border-radius: 6px;
            font-size: 0.85rem;
            cursor: pointer;
            transition: all 0.2s;
        }}
        .filter-btn:hover, .filter-btn.active {{
            background: var(--accent-blue);
            color: #000;
            font-weight: 600;
        }}

        .card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 1.5rem;
            margin-bottom: 1.25rem;
        }}
        .border-critical {{ border-left: 4px solid var(--accent-red); }}
        .border-high {{ border-left: 4px solid var(--accent-yellow); }}
        .border-medium {{ border-left: 4px solid var(--accent-blue); }}
        .border-low {{ border-left: 4px solid var(--accent-green); }}

        .card-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.75rem;
        }}
        .category-tag, .cwe-tag {{
            font-size: 0.75rem;
            color: var(--text-secondary);
            margin-left: 0.5rem;
        }}
        .rule-id {{
            font-family: monospace;
            font-size: 0.8rem;
            color: var(--text-secondary);
        }}
        .finding-title {{ font-size: 1.15rem; margin-bottom: 0.5rem; color: #fff; }}
        .finding-desc {{ color: var(--text-secondary); font-size: 0.95rem; margin-bottom: 0.75rem; }}
        
        .tag-row {{ display: flex; gap: 0.6rem; margin-bottom: 0.85rem; flex-wrap: wrap; }}
        .owasp-tag, .mitre-tag {{
            background: rgba(168,85,247,0.15);
            color: #c084fc;
            border: 1px solid rgba(168,85,247,0.3);
            padding: 0.15rem 0.5rem;
            border-radius: 4px;
            font-size: 0.78rem;
        }}
        
        .code-box, .fix-box {{
            background: #0d1117;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 0.85rem;
            margin-top: 0.75rem;
            font-family: ui-monospace, Menlo, Consolas, monospace;
            font-size: 0.85rem;
            overflow-x: auto;
        }}
        .code-header, .fix-header {{
            font-size: 0.75rem;
            color: var(--text-secondary);
            margin-bottom: 0.4rem;
            font-weight: 600;
        }}
        .fix-box {{
            border-color: rgba(0,255,136,0.3);
            background: rgba(0,255,136,0.03);
        }}
        .fix-header {{ color: var(--accent-green); }}
        .remediation-text {{
            margin-top: 0.85rem;
            font-size: 0.9rem;
            color: #e5e7eb;
        }}
        
        /* Footer */
        .footer {{
            margin-top: 4rem;
            padding-top: 1.5rem;
            border-top: 1px solid var(--border-color);
            text-align: center;
            color: var(--text-secondary);
            font-size: 0.85rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <header class="header">
            <div class="brand">
                <svg width="48" height="48" viewBox="0 0 100 100">
                    <path d="M50 10 L85 25 L85 60 Q85 85 50 95 Q15 85 15 60 L15 25 Z" fill="none" stroke="#00ff88" stroke-width="6"/>
                    <polyline points="35 50 45 60 65 40" fill="none" stroke="#00ff88" stroke-width="6" stroke-linecap="round"/>
                </svg>
                <div class="brand-text">
                    <h1>Sec<span>Skill</span> Agent &amp; MCP Auditor</h1>
                    <p>OWASP Top 10 for LLM &bull; MITRE ATLAS Compliance &bull; Target: <code>{html_lib.escape(report.target_path)}</code></p>
                </div>
            </div>
            <div class="score-box">
                <div class="score-circle">{score}</div>
                <div>
                    <div class="score-meta">TRUST INDEX</div>
                    <div class="grade-badge">Grade {grade}</div>
                </div>
            </div>
        </header>

        <!-- Metrics Grid -->
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-val" style="color:var(--accent-red);">{report.summary.get('CRITICAL', 0)}</div>
                <div class="metric-label">Critical Vulnerabilities</div>
            </div>
            <div class="metric-card">
                <div class="metric-val" style="color:var(--accent-yellow);">{report.summary.get('HIGH', 0)}</div>
                <div class="metric-label">High Severity Findings</div>
            </div>
            <div class="metric-card">
                <div class="metric-val" style="color:var(--accent-blue);">{report.stats.mcp_servers_found}</div>
                <div class="metric-label">MCP Servers Audited</div>
            </div>
            <div class="metric-card">
                <div class="metric-val" style="color:var(--accent-green);">{report.stats.total_files_audited}</div>
                <div class="metric-label">Agent Artifacts Inspected</div>
            </div>
        </div>

        <!-- Section: MCP Permission Matrix -->
        <h2 class="section-title">🔌 Model Context Protocol (MCP) Server Trust Matrix</h2>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Server Name</th>
                        <th>Executable / Command</th>
                        <th>Host Shell Access</th>
                        <th>Filesystem Scope</th>
                        <th>Environment Secrets</th>
                        <th>Remote Pinning</th>
                        <th>Posture</th>
                    </tr>
                </thead>
                <tbody>
                    {mcp_table_body}
                </tbody>
            </table>
        </div>

        <!-- Section: OWASP Top 10 for LLMs -->
        <h2 class="section-title">🗺️ OWASP Top 10 for LLM / MITRE ATLAS Vectors</h2>
        <div class="owasp-flex">
            {owasp_pills_html}
        </div>

        <!-- Section: Finding Explorer -->
        <h2 class="section-title">🛡️ Security Finding Details ({len(report.findings)})</h2>
        <div class="filter-bar">
            <button class="filter-btn active" onclick="filterFindings('all')">All Findings ({len(report.findings)})</button>
            <button class="filter-btn" onclick="filterFindings('critical')">Critical ({report.summary.get('CRITICAL', 0)})</button>
            <button class="filter-btn" onclick="filterFindings('high')">High ({report.summary.get('HIGH', 0)})</button>
            <button class="filter-btn" onclick="filterFindings('medium')">Medium ({report.summary.get('MEDIUM', 0)})</button>
        </div>

        <div id="findings-container">
            {findings_rendered}
        </div>

        <!-- Footer -->
        <footer class="footer">
            <p>Generated by <strong>SecSkill v0.1.0</strong> &bull; Agent-Native Security &amp; Static Analysis Engine &bull; {report.timestamp}</p>
        </footer>
    </div>

    <script>
        function filterFindings(sev) {{
            const cards = document.querySelectorAll('.finding-card');
            const btns = document.querySelectorAll('.filter-btn');
            btns.forEach(b => b.classList.remove('active'));
            event.target.classList.add('active');

            cards.forEach(card => {{
                if (sev === 'all' || card.getAttribute('data-severity') === sev) {{
                    card.style.display = 'block';
                }} else {{
                    card.style.display = 'none';
                }}
            }});
        }}
    </script>
</body>
</html>
"""
        if output_path:
            output_path.write_text(html_doc, encoding="utf-8")
        return html_doc

