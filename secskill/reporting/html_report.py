"""Interactive HTML report generator for SecSkill scan reports."""
import html as html_lib
from pathlib import Path
from typing import Optional
from secskill.reporting.base import BaseReporter
from secskill.models import ScanReport, Severity

class HtmlReporter(BaseReporter):
    """Generates a standalone, dark/light responsive HTML security dashboard for scan reports."""

    def generate(self, report: ScanReport, output_path: Optional[Path] = None) -> str:
        total = len(report.findings)
        counts = {sev.value: 0 for sev in Severity}
        for f in report.findings:
            sev_key = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            counts[sev_key] = counts.get(sev_key, 0) + 1

        crit_count = counts.get("CRITICAL", 0)
        high_count = counts.get("HIGH", 0)
        med_count = counts.get("MEDIUM", 0)
        low_count = counts.get("LOW", 0)

        # Build Finding Cards
        finding_cards = []
        for idx, f in enumerate(report.findings, start=1):
            sev_val = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            sev_class = sev_val.lower()
            snippet_html = ""
            if f.code_snippet:
                snippet_html = f"""
                <div class="code-snippet">
                    <div class="code-header">{html_lib.escape(f.file_path)}:{f.line_number}</div>
                    <pre><code>{html_lib.escape(f.code_snippet)}</code></pre>
                </div>
                """
            remediation_html = ""
            if f.remediation:
                remediation_html = f"""
                <div class="remediation-box">
                    <strong>Remediation:</strong> {html_lib.escape(f.remediation)}
                </div>
                """

            cwe_badge = f'<span class="badge badge-subtle">{html_lib.escape(f.cwe_id)}</span>' if f.cwe_id else ""
            owasp_badge = f'<span class="badge badge-subtle">{html_lib.escape(f.owasp_category)}</span>' if f.owasp_category else ""

            card = f"""
            <article class="card finding-card severity-{sev_class}">
                <header class="card-header">
                    <div class="badge-group">
                        <span class="badge badge-{sev_class}">{sev_val}</span>
                        <span class="badge badge-outline">{html_lib.escape(f.rule_id)}</span>
                        {cwe_badge}
                        {owasp_badge}
                    </div>
                    <span class="finding-loc">{html_lib.escape(f.file_path)}:{f.line_number}</span>
                </header>
                <h3 class="card-title">{html_lib.escape(f.title)}</h3>
                <p class="card-desc">{html_lib.escape(f.description)}</p>
                {snippet_html}
                {remediation_html}
            </article>
            """
            finding_cards.append(card)

        cards_body = "\n".join(finding_cards) if finding_cards else '<div class="empty-state">No security vulnerabilities detected within the scanned scope.</div>'

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecSkill Security Report — {html_lib.escape(report.target_path)}</title>
    <style>
        :root {{
            --bg: #0d1117;
            --surface: #161b22;
            --surface-border: #30363d;
            --text-main: #c9d1d9;
            --text-muted: #8b949e;
            --text-bright: #f0f6fc;
            --crit: #f85149;
            --crit-bg: rgba(248, 81, 73, 0.15);
            --high: #d29922;
            --high-bg: rgba(210, 153, 34, 0.15);
            --med: #e3b341;
            --med-bg: rgba(227, 179, 65, 0.15);
            --low: #58a6ff;
            --low-bg: rgba(88, 166, 255, 0.15);
            --accent: #2ea043;
            --code-bg: #0b0e14;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text-main);
            line-height: 1.6;
            padding: 2rem 1.5rem;
        }}
        .container {{ max-width: 1100px; margin: 0 auto; }}
        header.dashboard-header {{
            border-bottom: 1px solid var(--surface-border);
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
        }}
        .brand-title {{ font-size: 1.8rem; font-weight: 700; color: var(--text-bright); }}
        .brand-sub {{ color: var(--text-muted); font-size: 0.9rem; margin-top: 0.25rem; }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 1rem;
            margin-bottom: 2.5rem;
        }}
        .metric-card {{
            background: var(--surface);
            border: 1px solid var(--surface-border);
            border-radius: 8px;
            padding: 1.25rem;
            text-align: center;
        }}
        .metric-card.crit {{ border-top: 3px solid var(--crit); }}
        .metric-card.high {{ border-top: 3px solid var(--high); }}
        .metric-card.med {{ border-top: 3px solid var(--med); }}
        .metric-card.low {{ border-top: 3px solid var(--low); }}
        .metric-value {{ font-size: 2.2rem; font-weight: 800; color: var(--text-bright); }}
        .metric-label {{ font-size: 0.85rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; }}
        .findings-list {{ display: flex; flex-direction: column; gap: 1.25rem; }}
        .card {{
            background: var(--surface);
            border: 1px solid var(--surface-border);
            border-radius: 8px;
            padding: 1.5rem;
            transition: transform 0.15s ease, border-color 0.15s ease;
        }}
        .card:hover {{ border-color: #58a6ff; transform: translateY(-1px); }}
        .card.severity-critical {{ border-left: 4px solid var(--crit); }}
        .card.severity-high {{ border-left: 4px solid var(--high); }}
        .card.severity-medium {{ border-left: 4px solid var(--med); }}
        .card.severity-low {{ border-left: 4px solid var(--low); }}
        .card-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem; flex-wrap: wrap; gap: 0.5rem; }}
        .badge-group {{ display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap; }}
        .badge {{
            font-size: 0.75rem;
            font-weight: 700;
            padding: 0.2rem 0.55rem;
            border-radius: 4px;
            text-transform: uppercase;
        }}
        .badge-critical {{ background: var(--crit-bg); color: var(--crit); border: 1px solid var(--crit); }}
        .badge-high {{ background: var(--high-bg); color: var(--high); border: 1px solid var(--high); }}
        .badge-medium {{ background: var(--med-bg); color: var(--med); border: 1px solid var(--med); }}
        .badge-low {{ background: var(--low-bg); color: var(--low); border: 1px solid var(--low); }}
        .badge-outline {{ border: 1px solid var(--surface-border); color: var(--text-muted); }}
        .badge-subtle {{ background: rgba(255, 255, 255, 0.06); color: var(--text-main); font-weight: 500; }}
        .finding-loc {{ font-family: monospace; font-size: 0.85rem; color: var(--text-muted); }}
        .card-title {{ font-size: 1.2rem; color: var(--text-bright); margin-bottom: 0.5rem; }}
        .card-desc {{ color: var(--text-main); font-size: 0.95rem; margin-bottom: 1rem; }}
        .code-snippet {{
            background: var(--code-bg);
            border: 1px solid var(--surface-border);
            border-radius: 6px;
            margin-bottom: 1rem;
            overflow: hidden;
            font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
        }}
        .code-header {{
            background: rgba(255, 255, 255, 0.03);
            border-bottom: 1px solid var(--surface-border);
            padding: 0.35rem 0.75rem;
            font-size: 0.8rem;
            color: var(--text-muted);
        }}
        .code-snippet pre {{ padding: 0.75rem; overflow-x: auto; font-size: 0.88rem; color: #79c0ff; }}
        .remediation-box {{
            background: rgba(46, 160, 67, 0.1);
            border-left: 3px solid var(--accent);
            padding: 0.75rem 1rem;
            border-radius: 0 4px 4px 0;
            font-size: 0.9rem;
            color: #7ee787;
        }}
        .empty-state {{
            text-align: center;
            padding: 4rem 2rem;
            background: var(--surface);
            border: 1px dashed var(--surface-border);
            border-radius: 8px;
            color: var(--text-muted);
            font-size: 1.1rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header class="dashboard-header">
            <div>
                <h1 class="brand-title">SecSkill Security Report</h1>
                <div class="brand-sub">Target: <code>{html_lib.escape(report.target_path)}</code> | Timestamp: {html_lib.escape(report.timestamp)}</div>
            </div>
            <div>
                <span class="badge badge-outline">Scan ID: {html_lib.escape(report.scan_id[:8])}</span>
            </div>
        </header>

        <section class="metrics-grid">
            <div class="metric-card crit">
                <div class="metric-value">{crit_count}</div>
                <div class="metric-label">Critical</div>
            </div>
            <div class="metric-card high">
                <div class="metric-value">{high_count}</div>
                <div class="metric-label">High</div>
            </div>
            <div class="metric-card med">
                <div class="metric-value">{med_count}</div>
                <div class="metric-label">Medium</div>
            </div>
            <div class="metric-card low">
                <div class="metric-value">{low_count}</div>
                <div class="metric-label">Low</div>
            </div>
        </section>

        <section class="findings-list">
            {cards_body}
        </section>
    </div>
</body>
</html>"""

        if output_path:
            output_path.write_text(html_content, encoding="utf-8")
        return html_content

