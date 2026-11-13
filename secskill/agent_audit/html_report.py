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
            score_color = "#2ed573"
            score_bg = "#eefcf4"
        elif score >= 75:
            score_color = "#70a1ff"
            score_bg = "#f2f7ff"
        elif score >= 50:
            score_color = "#ff9f43"
            score_bg = "#fff9f0"
        else:
            score_color = "#ff5252"
            score_bg = "#fff5f5"

        # Build MCP Server Rows
        mcp_rows_html = []
        for s in report.mcp_servers:
            shell_badge = '<span class="badge badge-crit">EXPOSED SHELL</span>' if s.has_shell_access else '<span class="badge badge-safe">RESTRICTED</span>'
            root_badge = '<span class="badge badge-high">ROOT / HOME</span>' if s.has_filesystem_root else '<span class="badge badge-safe">SCOPED</span>'
            env_badge = '<span class="badge badge-high">RAW SECRET</span>' if s.has_raw_env_secrets else '<span class="badge badge-safe">SECURE</span>'
            pin_badge = '<span class="badge badge-safe">PINNED</span>' if s.is_pinned else '<span class="badge badge-med">UNPINNED</span>'

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
        mcp_table_body = "\n".join(mcp_rows_html) if mcp_rows_html else "<tr><td colspan='7' style='text-align:center; color:#52525b; font-weight:600;'>No standalone MCP servers detected in target scope.</td></tr>"

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
                    <div class="fix-header">
                        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
                        Proposed Remediation Patch
                    </div>
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
                    <span class="owasp-tag">
                        <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                        {html_lib.escape(f.owasp_llm)}
                    </span>
                    <span class="mitre-tag">
                        <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polygon points="3 6 9 3 15 6 21 3 21 18 15 21 9 18 3 21"/></svg>
                        {html_lib.escape(f.mitre_atlas)}
                    </span>
                </div>
                {code_block}
                <div class="remediation-text"><strong>Remediation:</strong> {html_lib.escape(f.remediation)}</div>
                {fix_block}
            </div>
            """)
        findings_rendered = "\n".join(findings_html) if findings_html else "<div class='card' style='text-align:center; padding:3rem; font-weight:800; font-family:var(--font-sans); color:#008744;'>🛡️ No agent or MCP vulnerabilities detected! Excellent posture.</div>"

        # OWASP Summary Cards
        owasp_items = []
        for owasp_k, count in report.owasp_llm_summary.items():
            owasp_items.append(f"""
            <div class="owasp-pill">
                <span class="owasp-count">{count}</span>
                <span class="owasp-label">{html_lib.escape(owasp_k)}</span>
            </div>
            """)
        owasp_pills_html = "\n".join(owasp_items) if owasp_items else "<div style='color:#52525b; font-weight:600;'>Zero OWASP LLM violations.</div>"

        html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecSkill AI Agent &amp; MCP Security Audit Report // Neubrutalism Terminal</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700;800&family=Space+Grotesk:wght@500;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-canvas: #f8f7f2;
            --bg-card: #ffffff;
            --bg-subtle: #f3f2eb;
            --bg-inset: #eae8df;
            --border-black: #000000;
            --border-main: 2.5px solid #000000;
            --border-thin: 1.5px solid #000000;

            --shadow-hard: 4px 4px 0px #000000;
            --shadow-small: 2px 2px 0px #000000;
            --shadow-large: 6px 6px 0px #000000;

            --text-ink: #121212;
            --text-muted: #52525b;
            --text-dim: #71717a;

            --accent-yellow: #ffdf59;
            --accent-red: #ff5252;
            --accent-orange: #ff9f43;
            --accent-amber: #ffd32a;
            --accent-green: #2ed573;
            --accent-blue: #70a1ff;
            --accent-purple: #a29bfe;

            --font-sans: 'Space Grotesk', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            --font-mono: 'JetBrains Mono', 'SF Mono', Consolas, 'Courier New', monospace;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}

        /* Custom crisp scrollbar */
        ::-webkit-scrollbar {{ width: 8px; height: 8px; }}
        ::-webkit-scrollbar-track {{ background: var(--bg-canvas); }}
        ::-webkit-scrollbar-thumb {{ background: #000000; border-radius: 4px; border: 2px solid var(--bg-canvas); }}
        ::-webkit-scrollbar-thumb:hover {{ background: #333333; }}

        body {{
            background-color: var(--bg-canvas);
            background-image: radial-gradient(#d3cec4 1.25px, transparent 1.25px);
            background-size: 24px 24px;
            color: var(--text-ink);
            font-family: var(--font-sans);
            line-height: 1.5;
            padding: 2.5rem 1.5rem;
            min-height: 100vh;
        }}
        .container {{ max-width: 1220px; margin: 0 auto; }}
        
        /* Neubrutalist Header */
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1.5rem;
            background: var(--bg-card);
            border: var(--border-main);
            border-radius: 10px;
            box-shadow: var(--shadow-hard);
            margin-bottom: 2rem;
            flex-wrap: wrap;
            gap: 1.25rem;
        }}
        .brand {{ display: flex; align-items: center; gap: 1.15rem; }}
        .brand-icon {{
            width: 52px;
            height: 52px;
            background: var(--accent-yellow);
            border: var(--border-main);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
            box-shadow: var(--shadow-small);
            color: #000000;
        }}
        .brand-text .system-badge {{
            font-family: var(--font-mono);
            font-size: 0.72rem;
            font-weight: 800;
            background: var(--accent-yellow);
            border: var(--border-thin);
            box-shadow: 2px 2px 0px #000;
            padding: 0.15rem 0.55rem;
            border-radius: 4px;
            letter-spacing: 0.05em;
            text-transform: uppercase;
            display: inline-flex;
            align-items: center;
            gap: 0.45rem;
            margin-bottom: 0.35rem;
            color: #000;
        }}
        .pulse-dot {{
            width: 8px;
            height: 8px;
            background: #000;
            border-radius: 50%;
            display: inline-block;
        }}
        .brand-text h1 {{
            font-family: var(--font-sans);
            font-size: 1.65rem;
            font-weight: 800;
            letter-spacing: -0.02em;
            color: #000000;
        }}
        .brand-text h1 span {{
            background: var(--accent-yellow);
            padding: 0 0.3rem;
            border: 2px solid #000;
            border-radius: 4px;
            margin: 0 0.15rem;
            box-shadow: 2px 2px 0px #000;
        }}
        .brand-text p {{
            color: var(--text-muted);
            font-size: 0.85rem;
            font-family: var(--font-mono);
            font-weight: 500;
            margin-top: 0.25rem;
        }}

        /* Score Gauge Instrument */
        .score-box {{
            display: flex;
            align-items: center;
            gap: 1.25rem;
            background: {score_bg};
            padding: 1.15rem 1.6rem;
            border-radius: 8px;
            border: var(--border-main);
            box-shadow: var(--shadow-small);
            transition: transform 0.15s, box-shadow 0.15s;
        }}
        .score-box:hover {{
            transform: translate(-1px, -1px);
            box-shadow: 3px 3px 0px #000000;
        }}
        .score-circle {{
            font-family: var(--font-mono);
            font-size: 2.5rem;
            font-weight: 900;
            color: #000000;
            line-height: 1;
        }}
        .score-meta {{
            font-size: 0.72rem;
            color: var(--text-muted);
            font-family: var(--font-mono);
            font-weight: 800;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }}
        .grade-badge {{
            display: inline-block;
            background: {score_color};
            color: #ffffff;
            border: var(--border-thin);
            box-shadow: 2px 2px 0px #000;
            padding: 0.2rem 0.65rem;
            border-radius: 4px;
            font-weight: 800;
            font-size: 0.95rem;
            font-family: var(--font-mono);
            letter-spacing: 0.05em;
            margin-top: 0.25rem;
        }}

        /* Metrics Row */
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
            gap: 1.25rem;
            margin-bottom: 2.25rem;
        }}
        .metric-card {{
            background: var(--bg-card);
            border: var(--border-main);
            border-radius: 10px;
            padding: 1.4rem;
            box-shadow: var(--shadow-hard);
            transition: transform 0.15s, box-shadow 0.15s;
            display: flex;
            align-items: center;
            gap: 1.25rem;
        }}
        .metric-card:hover {{
            transform: translate(-2px, -2px);
            box-shadow: var(--shadow-large);
        }}
        .metric-card:nth-child(1) {{ background: #fff5f5; }}
        .metric-card:nth-child(2) {{ background: #fff9f0; }}
        .metric-card:nth-child(3) {{ background: #f2f7ff; }}
        .metric-card:nth-child(4) {{ background: #f0fdf4; }}

        .metric-icon {{
            width: 50px;
            height: 50px;
            background: #ffffff;
            border: var(--border-main);
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: var(--shadow-small);
            flex-shrink: 0;
            color: #000000;
        }}
        .metric-card:nth-child(1) .metric-icon {{ background: var(--accent-red); color: #ffffff; }}
        .metric-card:nth-child(2) .metric-icon {{ background: var(--accent-orange); color: #ffffff; }}
        .metric-card:nth-child(3) .metric-icon {{ background: var(--accent-blue); color: #000000; }}
        .metric-card:nth-child(4) .metric-icon {{ background: var(--accent-green); color: #ffffff; }}

        .metric-val {{
            font-family: var(--font-mono);
            font-size: 2.2rem;
            font-weight: 900;
            line-height: 1;
            letter-spacing: -0.02em;
            color: #000000;
        }}
        .metric-label {{
            color: var(--text-muted);
            font-size: 0.75rem;
            font-family: var(--font-mono);
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            margin-top: 0.2rem;
        }}

        /* Section Titles */
        .section-title {{
            font-family: var(--font-sans);
            font-size: 1.2rem;
            font-weight: 800;
            letter-spacing: -0.01em;
            color: #000000;
            margin: 2.5rem 0 1rem 0;
            display: flex;
            align-items: center;
            gap: 0.65rem;
        }}
        .section-title svg {{
            color: #000000;
            flex-shrink: 0;
        }}

        /* MCP Table */
        .table-wrap {{
            overflow-x: auto;
            background: var(--bg-card);
            border: var(--border-main);
            border-radius: 10px;
            margin-bottom: 2.5rem;
            box-shadow: var(--shadow-hard);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.88rem;
            text-align: left;
        }}
        th, td {{
            padding: 0.9rem 1.1rem;
            border-bottom: 2px solid #000000;
        }}
        th {{
            background: var(--bg-subtle);
            color: #000000;
            font-family: var(--font-mono);
            font-weight: 800;
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            border-bottom: var(--border-main);
        }}
        tbody tr:hover {{
            background: #faf8f5;
        }}
        code {{
            background: #18191f;
            border: var(--border-thin);
            padding: 0.2rem 0.55rem;
            border-radius: 4px;
            font-family: var(--font-mono);
            font-size: 0.82rem;
            color: #4ade80;
            font-weight: 600;
        }}

        /* Badges */
        .badge {{
            display: inline-block;
            padding: 0.22rem 0.65rem;
            border-radius: 4px;
            font-size: 0.72rem;
            font-family: var(--font-mono);
            font-weight: 800;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            border: var(--border-thin);
            box-shadow: 2px 2px 0px #000000;
            color: #000000;
        }}
        .badge-crit {{ background: var(--accent-red); color: #ffffff; }}
        .badge-high {{ background: var(--accent-orange); color: #ffffff; }}
        .badge-med {{ background: var(--accent-amber); color: #000000; }}
        .badge-low, .badge-safe {{ background: var(--accent-green); color: #ffffff; }}

        /* OWASP Pills */
        .owasp-flex {{ display: flex; flex-wrap: wrap; gap: 0.65rem; margin-bottom: 2.25rem; }}
        .owasp-pill {{
            background: var(--bg-card);
            border: var(--border-main);
            box-shadow: var(--shadow-small);
            padding: 0.5rem 0.9rem;
            border-radius: 6px;
            display: flex;
            align-items: center;
            gap: 0.65rem;
            font-size: 0.8rem;
            font-family: var(--font-mono);
            font-weight: 700;
            transition: transform 0.15s, box-shadow 0.15s;
        }}
        .owasp-pill:hover {{
            transform: translate(-1px, -1px);
            box-shadow: 3px 3px 0px #000;
        }}
        .owasp-count {{
            background: var(--accent-red);
            color: #ffffff;
            font-weight: 900;
            padding: 0.12rem 0.55rem;
            border-radius: 4px;
            border: var(--border-thin);
            box-shadow: 1px 1px 0px #000;
        }}
        .owasp-label {{ color: #000000; }}

        /* Findings Explorer */
        .filter-bar {{
            display: flex;
            gap: 0.5rem;
            margin-bottom: 1.5rem;
            flex-wrap: wrap;
        }}
        .filter-btn {{
            background: #ffffff;
            border: var(--border-thin);
            box-shadow: var(--shadow-small);
            color: #000000;
            padding: 0.55rem 1rem;
            border-radius: 6px;
            font-size: 0.8rem;
            font-family: var(--font-mono);
            font-weight: 700;
            letter-spacing: 0.04em;
            text-transform: uppercase;
            cursor: pointer;
            transition: transform 0.1s, box-shadow 0.1s, background-color 0.1s;
        }}
        .filter-btn:hover {{
            background: var(--bg-subtle);
            transform: translate(-1px, -1px);
            box-shadow: 3px 3px 0px #000000;
        }}
        .filter-btn.active {{
            background: var(--accent-yellow);
            color: #000000;
            font-weight: 800;
            transform: translate(1px, 1px);
            box-shadow: 2px 2px 0px #000000;
        }}

        .card {{
            background: var(--bg-card);
            border: var(--border-main);
            border-radius: 10px;
            padding: 1.4rem;
            margin-bottom: 1.25rem;
            box-shadow: var(--shadow-hard);
            position: relative;
            transition: transform 0.15s, box-shadow 0.15s;
        }}
        .card:hover {{
            transform: translate(-2px, -2px);
            box-shadow: var(--shadow-large);
        }}
        .border-critical {{ border-left: 8px solid var(--accent-red); }}
        .border-high {{ border-left: 8px solid var(--accent-orange); }}
        .border-medium {{ border-left: 8px solid var(--accent-amber); }}
        .border-low {{ border-left: 8px solid var(--accent-green); }}

        .card-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.85rem;
            flex-wrap: wrap;
            gap: 0.5rem;
        }}
        .category-tag, .cwe-tag {{
            font-family: var(--font-mono);
            font-size: 0.75rem;
            font-weight: 700;
            color: var(--text-muted);
            margin-left: 0.45rem;
        }}
        .rule-id {{
            font-family: var(--font-mono);
            font-size: 0.75rem;
            font-weight: 700;
            color: #000000;
            background: var(--bg-subtle);
            padding: 0.2rem 0.55rem;
            border-radius: 4px;
            border: var(--border-thin);
            letter-spacing: 0.04em;
        }}
        .finding-title {{
            font-family: var(--font-sans);
            font-size: 1.1rem;
            font-weight: 700;
            margin-bottom: 0.45rem;
            color: #000000;
            letter-spacing: -0.01em;
        }}
        .finding-desc {{
            color: #27272a;
            font-size: 0.92rem;
            margin-bottom: 0.85rem;
            line-height: 1.6;
            font-weight: 500;
        }}
        
        .tag-row {{ display: flex; gap: 0.5rem; margin-bottom: 0.85rem; flex-wrap: wrap; }}
        .owasp-tag, .mitre-tag {{
            background: var(--bg-subtle);
            color: #000000;
            border: var(--border-thin);
            box-shadow: 2px 2px 0px #000;
            padding: 0.2rem 0.55rem;
            border-radius: 4px;
            font-family: var(--font-mono);
            font-size: 0.75rem;
            font-weight: 700;
            display: inline-flex;
            align-items: center;
            gap: 0.4rem;
        }}
        
        .code-box, .fix-box {{
            border: var(--border-main);
            box-shadow: var(--shadow-small);
            border-radius: 6px;
            overflow: hidden;
            margin-top: 0.85rem;
            font-family: var(--font-mono);
            font-size: 0.85rem;
            line-height: 1.5;
        }}
        .code-box {{
            background: #18191f;
        }}
        .code-header {{
            background: #272833;
            padding: 0.45rem 1rem;
            font-size: 0.75rem;
            color: #a1a1aa;
            font-family: var(--font-mono);
            font-weight: 700;
            border-bottom: 2px solid #000000;
            letter-spacing: 0.05em;
        }}
        .code-box pre {{
            padding: 0.85rem 1rem;
            overflow-x: auto;
            color: #4ade80;
        }}
        .fix-box {{
            background: #eefcf4;
            padding: 0.9rem 1.1rem;
        }}
        .fix-header {{
            color: #008744;
            font-size: 0.82rem;
            font-family: var(--font-mono);
            font-weight: 800;
            letter-spacing: 0.04em;
            margin-bottom: 0.5rem;
            display: flex;
            align-items: center;
            gap: 0.45rem;
        }}
        .fix-box pre code {{
            background: transparent;
            border: none;
            color: #121212;
            padding: 0;
            font-weight: 600;
        }}
        .remediation-text {{
            margin-top: 0.85rem;
            font-size: 0.88rem;
            font-family: var(--font-mono);
            color: #121212;
            line-height: 1.5;
            font-weight: 600;
        }}
        
        /* Footer */
        .footer {{
            margin-top: 3.5rem;
            text-align: center;
            color: #000000;
            background: var(--bg-card);
            border: var(--border-main);
            box-shadow: var(--shadow-small);
            border-radius: 8px;
            padding: 1.15rem;
            font-size: 0.8rem;
            font-family: var(--font-mono);
            font-weight: 700;
            letter-spacing: 0.04em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Neubrutalist Header -->
        <header class="header">
            <div class="brand">
                <div class="brand-icon">
                    <svg viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    </svg>
                </div>
                <div class="brand-text">
                    <div class="system-badge"><span class="pulse-dot"></span> [ AUDIT.ENGINE // OWASP-LLM-MITRE ]</div>
                    <h1>Sec<span>Skill</span> Agent &amp; MCP Auditor</h1>
                    <p>// OWASP Top 10 for LLM &bull; MITRE ATLAS Compliance &bull; Target: <code>{html_lib.escape(report.target_path)}</code></p>
                </div>
            </div>
            <div class="score-box">
                <div class="score-circle">{score}</div>
                <div>
                    <div class="score-meta">// TRUST INDEX</div>
                    <div class="grade-badge">[ GRADE {grade} ]</div>
                </div>
            </div>
        </header>

        <!-- Metrics Grid -->
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-icon">
                    <svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                        <polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2"/>
                        <line x1="12" y1="8" x2="12" y2="12"/>
                        <line x1="12" y1="16" x2="12.01" y2="16"/>
                    </svg>
                </div>
                <div>
                    <div class="metric-val">{report.summary.get('CRITICAL', 0)}</div>
                    <div class="metric-label">// Critical Findings</div>
                </div>
            </div>
            <div class="metric-card">
                <div class="metric-icon">
                    <svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                        <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/>
                        <line x1="12" y1="9" x2="12" y2="13"/>
                        <line x1="12" y1="17" x2="12.01" y2="17"/>
                    </svg>
                </div>
                <div>
                    <div class="metric-val">{report.summary.get('HIGH', 0)}</div>
                    <div class="metric-label">// High Severity</div>
                </div>
            </div>
            <div class="metric-card">
                <div class="metric-icon">
                    <svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                        <rect width="20" height="8" x="2" y="2" rx="2" ry="2"/>
                        <rect width="20" height="8" x="2" y="14" rx="2" ry="2"/>
                        <line x1="6" y1="6" x2="6.01" y2="6"/>
                        <line x1="6" y1="18" x2="6.01" y2="18"/>
                    </svg>
                </div>
                <div>
                    <div class="metric-val">{report.stats.mcp_servers_found}</div>
                    <div class="metric-label">// MCP Servers Scanned</div>
                </div>
            </div>
            <div class="metric-card">
                <div class="metric-icon">
                    <svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/>
                        <polyline points="14 2 14 8 20 8"/>
                        <polyline points="10 13 8 15 10 17"/>
                        <polyline points="14 13 16 15 14 17"/>
                    </svg>
                </div>
                <div>
                    <div class="metric-val">{report.stats.total_files_audited}</div>
                    <div class="metric-label">// Artifacts Inspected</div>
                </div>
            </div>
        </div>

        <!-- Section: MCP Permission Matrix -->
        <h2 class="section-title">
            <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2v8"/><path d="m4.93 10.93 1.41 1.41"/><path d="M2 18h2"/><path d="M20 18h2"/><path d="m19.07 10.93-1.41 1.41"/><path d="M22 22H2"/><path d="m16 6-4 4-4-4"/><path d="M16 18a4 4 0 0 0-8 0"/></svg>
            MODEL CONTEXT PROTOCOL (MCP) TRUST MATRIX
        </h2>
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
        <h2 class="section-title">
            <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polygon points="3 6 9 3 15 6 21 3 21 18 15 21 9 18 3 21"/><line x1="9" y1="3" x2="9" y2="18"/><line x1="15" y1="6" x2="15" y2="21"/></svg>
            OWASP TOP 10 FOR LLM / MITRE ATLAS VECTORS
        </h2>
        <div class="owasp-flex">
            {owasp_pills_html}
        </div>

        <!-- Section: Finding Explorer -->
        <h2 class="section-title">
            <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            SECURITY FINDING DETAILS ({len(report.findings)})
        </h2>
        <div class="filter-bar">
            <button class="filter-btn active" onclick="filterFindings('all', this)">[ ALL: {len(report.findings)} ]</button>
            <button class="filter-btn" onclick="filterFindings('critical', this)">[ CRIT: {report.summary.get('CRITICAL', 0)} ]</button>
            <button class="filter-btn" onclick="filterFindings('high', this)">[ HIGH: {report.summary.get('HIGH', 0)} ]</button>
            <button class="filter-btn" onclick="filterFindings('medium', this)">[ MED: {report.summary.get('MEDIUM', 0)} ]</button>
        </div>

        <div id="findings-container">
            {findings_rendered}
        </div>

        <!-- Footer -->
        <footer class="footer">
            <p>// SECSKILL AUDIT TERMINAL &bull; AGENT-NATIVE STATIC ANALYSIS ENGINE &bull; {report.timestamp}</p>
        </footer>
    </div>

    <script>
        function filterFindings(sev, btn) {{
            const cards = document.querySelectorAll('.finding-card');
            const btns = document.querySelectorAll('.filter-btn');
            btns.forEach(b => b.classList.remove('active'));
            if (btn) {{
                btn.classList.add('active');
            }} else if (window.event && window.event.target) {{
                window.event.target.classList.add('active');
            }}

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

