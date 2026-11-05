"""Standalone interactive dark-mode visual dashboard reporter for SecSkill."""
import json
import html as html_lib
from pathlib import Path
from typing import Optional, Dict, Any, List
from secskill.reporting.base import BaseReporter
from secskill.models import ScanReport, Finding, Severity

def calculate_security_score(report: ScanReport) -> Dict[str, Any]:
    """Calculate 0-100 security score and letter grade."""
    score = 100
    crits = sum(1 for f in report.findings if f.severity == Severity.CRITICAL)
    highs = sum(1 for f in report.findings if f.severity == Severity.HIGH)
    meds = sum(1 for f in report.findings if f.severity == Severity.MEDIUM)
    lows = sum(1 for f in report.findings if f.severity == Severity.LOW)

    score -= (crits * 25) + (highs * 15) + (meds * 5) + (lows * 2)
    score = max(0, min(100, score))

    if score >= 95:
        grade = "A+"
        color = "#10b981"
        status = "EXCELLENT"
    elif score >= 85:
        grade = "A"
        color = "#22c55e"
        status = "GOOD"
    elif score >= 70:
        grade = "B"
        color = "#eab308"
        status = "ACCEPTABLE"
    elif score >= 50:
        grade = "C"
        color = "#f97316"
        status = "NEEDS ATTENTION"
    else:
        grade = "F"
        color = "#ef4444"
        status = "CRITICAL RISK"

    return {
        "score": score,
        "grade": grade,
        "color": color,
        "status": status,
        "critical": crits,
        "high": highs,
        "medium": meds,
        "low": lows,
        "total": len(report.findings),
    }

class HtmlReporter(BaseReporter):
    """Generates an interactive, dark-mode visual web dashboard."""

    def generate(self, report: ScanReport, output_path: Optional[Path] = None) -> str:
        score_info = calculate_security_score(report)
        findings_json = json.dumps([f.model_dump() for f in report.findings])
        
        # Stroke dash for radial gauge (circumference of r=52 is ~326.7)
        circumference = 326.7
        offset = circumference - (circumference * score_info["score"] / 100)

        # Build cards
        cards_html = []
        for idx, f in enumerate(report.findings):
            sev_class = f.severity.value.lower()
            snippet = html_lib.escape(f.code_snippet or "No snippet available")
            rem = html_lib.escape(f.remediation or "Apply input sanitization and parameterized queries.")
            cwe = html_lib.escape(f.cwe_id or "CWE-General")
            owasp = html_lib.escape(f.owasp_category or "Security Best Practice")
            copy_payload = html_lib.escape(rem.replace("'", ""))
            
            cards_html.append(f"""
            <div class="finding-card severity-{sev_class}" data-severity="{sev_class}" data-text="{html_lib.escape(f.title.lower())} {html_lib.escape(f.file_path.lower())} {html_lib.escape(f.rule_id.lower())}">
                <div class="card-header" onclick="toggleCard({idx})">
                    <div class="card-title-group">
                        <span class="badge {sev_class}">{f.severity.value}</span>
                        <span class="rule-id">{html_lib.escape(f.rule_id)}</span>
                        <h3 class="card-title">{html_lib.escape(f.title)}</h3>
                    </div>
                    <div class="card-meta">
                        <span class="file-loc">📁 {html_lib.escape(f.file_path)}:<strong>{f.line_number}</strong></span>
                        <span class="expand-icon" id="icon-{idx}">▼</span>
                    </div>
                </div>
                <div class="card-body" id="body-{idx}">
                    <div class="pill-row">
                        <span class="cwe-pill">🔖 {cwe}</span>
                        <span class="owasp-pill">🛡️ {owasp}</span>
                    </div>
                    <p class="description">{html_lib.escape(f.description)}</p>
                    <div class="code-box">
                        <div class="code-header">
                            <span>Vulnerable Code Line {f.line_number}</span>
                        </div>
                        <pre><code>{snippet}</code></pre>
                    </div>
                    <div class="fix-box">
                        <div class="fix-header">
                            <span>💡 Recommended Remediation</span>
                            <button class="copy-btn" onclick="copyFix('{copy_payload}', this)">📋 Copy Fix</button>
                        </div>
                        <div class="fix-content">{rem}</div>
                    </div>
                </div>
            </div>
            """)

        cards_rendered = "\n".join(cards_html) if cards_html else """
        <div class="empty-state">
            <div class="empty-icon">🎉</div>
            <h2>All Clear! Zero Vulnerabilities Detected</h2>
            <p>Your codebase passed all security checks without any active findings.</p>
        </div>
        """

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecSkill Security Dashboard</title>
    <style>
        :root {{
            --bg-base: #0a0e17;
            --bg-card: #111827;
            --bg-card-hover: #1f2937;
            --border-subtle: #1e293b;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent-cyan: #06b6d4;
            --accent-blue: #3b82f6;
            --crit-color: #ef4444;
            --high-color: #f97316;
            --med-color: #eab308;
            --low-color: #3b82f6;
            --score-color: {score_info["color"]};
        }}

        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background: var(--bg-base);
            color: var(--text-main);
            line-height: 1.5;
            padding: 2rem 1.5rem;
            min-height: 100vh;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}

        /* Header */
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 1.5rem;
            border-bottom: 1px solid var(--border-subtle);
            margin-bottom: 2rem;
            flex-wrap: wrap;
            gap: 1rem;
        }}
        .logo-wrap {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }}
        .logo-icon {{
            font-size: 2.2rem;
        }}
        .logo-title h1 {{
            font-size: 1.6rem;
            font-weight: 800;
            letter-spacing: -0.02em;
            background: linear-gradient(135deg, #38bdf8 0%, #818cf8 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .logo-title p {{
            color: var(--text-muted);
            font-size: 0.85rem;
        }}
        .scan-meta {{
            display: flex;
            gap: 0.75rem;
            align-items: center;
        }}
        .meta-pill {{
            background: #1e293b;
            padding: 0.35rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.8rem;
            color: var(--text-muted);
            border: 1px solid #334155;
        }}

        /* Score & Overview Grid */
        .overview-grid {{
            display: grid;
            grid-template-columns: 320px 1fr;
            gap: 1.5rem;
            margin-bottom: 2rem;
        }}
        @media (max-width: 860px) {{
            .overview-grid {{ grid-template-columns: 1fr; }}
        }}

        .score-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-subtle);
            border-radius: 16px;
            padding: 1.75rem;
            display: flex;
            flex-direction: column;
            align-items: center;
            text-align: center;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.4);
            position: relative;
            overflow: hidden;
        }}
        .score-card::before {{
            content: "";
            position: absolute;
            top: 0; left: 0; right: 0; height: 4px;
            background: var(--score-color);
        }}

        .gauge-svg {{
            width: 150px;
            height: 150px;
            transform: rotate(-90deg);
        }}
        .gauge-bg {{
            fill: none;
            stroke: #1e293b;
            stroke-width: 10;
        }}
        .gauge-meter {{
            fill: none;
            stroke: var(--score-color);
            stroke-width: 10;
            stroke-linecap: round;
            stroke-dasharray: 326.7;
            stroke-dashoffset: {offset};
            transition: stroke-dashoffset 1s ease-in-out;
        }}
        .gauge-center {{
            position: absolute;
            top: 75px;
            display: flex;
            flex-direction: column;
            align-items: center;
        }}
        .grade-text {{
            font-size: 2.4rem;
            font-weight: 900;
            color: var(--score-color);
            line-height: 1;
        }}
        .score-num {{
            font-size: 0.9rem;
            color: var(--text-muted);
            margin-top: 0.2rem;
        }}
        .score-status {{
            margin-top: 1rem;
            font-weight: 700;
            letter-spacing: 0.05em;
            color: var(--score-color);
            font-size: 0.95rem;
        }}

        /* Metrics Row */
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 1rem;
        }}
        @media (max-width: 500px) {{
            .metrics-grid {{ grid-template-columns: 1fr; }}
        }}
        .metric-tile {{
            background: var(--bg-card);
            border: 1px solid var(--border-subtle);
            border-radius: 12px;
            padding: 1.25rem;
            display: flex;
            align-items: center;
            gap: 1rem;
            box-shadow: 0 4px 12px rgba(0,0,0,0.2);
        }}
        .metric-icon {{
            width: 48px;
            height: 48px;
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.5rem;
        }}
        .tile-crit .metric-icon {{ background: rgba(239, 68, 68, 0.15); color: #ef4444; }}
        .tile-high .metric-icon {{ background: rgba(249, 115, 22, 0.15); color: #f97316; }}
        .tile-med .metric-icon {{ background: rgba(234, 179, 8, 0.15); color: #eab308; }}
        .tile-total .metric-icon {{ background: rgba(6, 182, 212, 0.15); color: #06b6d4; }}

        .metric-content h4 {{
            font-size: 0.8rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        .metric-content .val {{
            font-size: 1.8rem;
            font-weight: 800;
            line-height: 1.2;
        }}

        /* Filter Controls */
        .filter-bar {{
            background: var(--bg-card);
            border: 1px solid var(--border-subtle);
            border-radius: 12px;
            padding: 0.75rem 1rem;
            display: flex;
            gap: 1rem;
            margin-bottom: 1.5rem;
            align-items: center;
            flex-wrap: wrap;
        }}
        .search-input {{
            flex: 1;
            min-width: 220px;
            background: #0f172a;
            border: 1px solid #334155;
            color: #f8fafc;
            padding: 0.5rem 1rem;
            border-radius: 8px;
            font-size: 0.9rem;
            outline: none;
        }}
        .search-input:focus {{
            border-color: var(--accent-cyan);
        }}
        .tabs {{
            display: flex;
            gap: 0.4rem;
        }}
        .tab-btn {{
            background: transparent;
            border: 1px solid transparent;
            color: var(--text-muted);
            padding: 0.4rem 0.8rem;
            border-radius: 8px;
            cursor: pointer;
            font-size: 0.85rem;
            font-weight: 600;
            transition: all 0.2s;
        }}
        .tab-btn:hover {{
            background: #1e293b;
            color: white;
        }}
        .tab-btn.active {{
            background: #1e293b;
            color: var(--accent-cyan);
            border-color: var(--accent-cyan);
        }}

        /* Finding Cards */
        .findings-list {{
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }}
        .finding-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-subtle);
            border-radius: 12px;
            overflow: hidden;
            transition: border-color 0.2s, transform 0.15s;
        }}
        .finding-card:hover {{
            border-color: #334155;
        }}
        .finding-card.severity-critical {{ border-left: 5px solid var(--crit-color); }}
        .finding-card.severity-high {{ border-left: 5px solid var(--high-color); }}
        .finding-card.severity-medium {{ border-left: 5px solid var(--med-color); }}
        .finding-card.severity-low {{ border-left: 5px solid var(--low-color); }}

        .card-header {{
            padding: 1.1rem 1.25rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            cursor: pointer;
            gap: 1rem;
            user-select: none;
        }}
        .card-title-group {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
            flex-wrap: wrap;
        }}
        .card-title {{
            font-size: 1rem;
            font-weight: 700;
        }}
        .rule-id {{
            color: var(--text-muted);
            font-family: monospace;
            font-size: 0.8rem;
            background: #0f172a;
            padding: 2px 6px;
            border-radius: 4px;
        }}
        .badge {{
            padding: 3px 8px;
            border-radius: 6px;
            font-weight: 800;
            font-size: 0.75rem;
            letter-spacing: 0.05em;
        }}
        .badge.critical {{ background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid #ef4444; }}
        .badge.high {{ background: rgba(249, 115, 22, 0.2); color: #f97316; border: 1px solid #f97316; }}
        .badge.medium {{ background: rgba(234, 179, 8, 0.2); color: #eab308; border: 1px solid #eab308; }}
        .badge.low {{ background: rgba(59, 130, 246, 0.2); color: #3b82f6; border: 1px solid #3b82f6; }}

        .card-meta {{
            display: flex;
            align-items: center;
            gap: 1rem;
            color: var(--text-muted);
            font-size: 0.85rem;
            white-space: nowrap;
        }}
        .expand-icon {{
            font-size: 0.75rem;
            transition: transform 0.2s;
        }}
        .card-body {{
            padding: 0 1.25rem 1.25rem 1.25rem;
            display: none;
            border-top: 1px solid #1e293b;
            margin-top: 0.5rem;
            padding-top: 1rem;
        }}
        .pill-row {{
            display: flex;
            gap: 0.5rem;
            margin-bottom: 0.75rem;
        }}
        .cwe-pill, .owasp-pill {{
            font-size: 0.75rem;
            background: #1e293b;
            padding: 2px 8px;
            border-radius: 4px;
            color: #94a3b8;
        }}
        .description {{
            color: #cbd5e1;
            font-size: 0.9rem;
            margin-bottom: 1rem;
        }}
        .code-box {{
            background: #090d16;
            border: 1px solid #1e293b;
            border-radius: 8px;
            overflow: hidden;
            margin-bottom: 1rem;
        }}
        .code-header {{
            background: #0f172a;
            padding: 4px 10px;
            font-size: 0.75rem;
            color: var(--text-muted);
            border-bottom: 1px solid #1e293b;
        }}
        .code-box pre {{
            padding: 0.75rem 1rem;
            overflow-x: auto;
            color: #f1f5f9;
            font-family: 'Fira Code', monospace;
            font-size: 0.85rem;
        }}
        .fix-box {{
            background: rgba(16, 185, 129, 0.05);
            border: 1px solid rgba(16, 185, 129, 0.2);
            border-radius: 8px;
            padding: 0.75rem 1rem;
        }}
        .fix-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-weight: 700;
            font-size: 0.85rem;
            color: #10b981;
            margin-bottom: 0.5rem;
        }}
        .copy-btn {{
            background: #10b981;
            color: black;
            border: none;
            padding: 3px 10px;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 700;
            cursor: pointer;
            transition: opacity 0.2s;
        }}
        .copy-btn:hover {{ opacity: 0.85; }}
        .fix-content {{
            font-size: 0.88rem;
            color: #e2e8f0;
        }}

        .empty-state {{
            background: var(--bg-card);
            border: 1px solid var(--border-subtle);
            border-radius: 16px;
            padding: 3rem;
            text-align: center;
        }}
        .empty-icon {{ font-size: 3rem; margin-bottom: 1rem; }}
        .empty-state h2 {{ margin-bottom: 0.5rem; color: #10b981; }}
        .empty-state p {{ color: var(--text-muted); }}

        footer {{
            margin-top: 3rem;
            text-align: center;
            color: var(--text-muted);
            font-size: 0.8rem;
            border-top: 1px solid var(--border-subtle);
            padding-top: 1.5rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <header>
            <div class="logo-wrap">
                <div class="logo-icon">🛡️</div>
                <div class="logo-title">
                    <h1>SecSkill Visual Security Hub</h1>
                    <p>Agent-Native Security Review & Diagnostic Dashboard</p>
                </div>
            </div>
            <div class="scan-meta">
                <span class="meta-pill">Target: <strong>{html_lib.escape(report.target_path)}</strong></span>
                <span class="meta-pill">Date: <strong>{report.timestamp[:19].replace('T', ' ')}</strong></span>
            </div>
        </header>

        <!-- Overview Section -->
        <section class="overview-grid">
            <!-- Radial Score Card -->
            <div class="score-card">
                <svg class="gauge-svg" viewBox="0 0 120 120">
                    <circle class="gauge-bg" cx="60" cy="60" r="52"></circle>
                    <circle class="gauge-meter" cx="60" cy="60" r="52"></circle>
                </svg>
                <div class="gauge-center">
                    <span class="grade-text">{score_info["grade"]}</span>
                    <span class="score-num">{score_info["score"]}/100</span>
                </div>
                <div class="score-status">{score_info["status"]}</div>
                <p style="color: var(--text-muted); font-size: 0.8rem; margin-top: 0.5rem;">Codebase Security Index</p>
            </div>

            <!-- 4 Metric Tiles -->
            <div class="metrics-grid">
                <div class="metric-tile tile-crit">
                    <div class="metric-icon">🚨</div>
                    <div class="metric-content">
                        <h4>Critical Risks</h4>
                        <div class="val">{score_info["critical"]}</div>
                    </div>
                </div>
                <div class="metric-tile tile-high">
                    <div class="metric-icon">⚠️</div>
                    <div class="metric-content">
                        <h4>High Vulnerabilities</h4>
                        <div class="val">{score_info["high"]}</div>
                    </div>
                </div>
                <div class="metric-tile tile-med">
                    <div class="metric-icon">⚡</div>
                    <div class="metric-content">
                        <h4>Medium / Low</h4>
                        <div class="val">{score_info["medium"] + score_info["low"]}</div>
                    </div>
                </div>
                <div class="metric-tile tile-total">
                    <div class="metric-icon">📋</div>
                    <div class="metric-content">
                        <h4>Total Findings</h4>
                        <div class="val">{score_info["total"]}</div>
                    </div>
                </div>
            </div>
        </section>

        <!-- Filter Bar -->
        <div class="filter-bar">
            <input type="text" id="search-input" class="search-input" placeholder="🔍 Search findings by file, rule, or keyword..." oninput="filterFindings()">
            <div class="tabs">
                <button class="tab-btn active" onclick="setTab('all', this)">All ({score_info["total"]})</button>
                <button class="tab-btn" onclick="setTab('critical', this)">Critical ({score_info["critical"]})</button>
                <button class="tab-btn" onclick="setTab('high', this)">High ({score_info["high"]})</button>
                <button class="tab-btn" onclick="setTab('medium', this)">Med / Low ({score_info["medium"] + score_info["low"]})</button>
            </div>
        </div>

        <!-- Finding Cards List -->
        <section class="findings-list" id="findings-list">
            {cards_rendered}
        </section>

        <footer>
            Built with ❤️ by SecSkill Maintainers • 100% Local & Privacy-Preserving Security Review
        </footer>
    </div>

    <script>
        let currentTab = 'all';

        function toggleCard(idx) {{
            const body = document.getElementById('body-' + idx);
            const icon = document.getElementById('icon-' + idx);
            if (body.style.display === 'block') {{
                body.style.display = 'none';
                icon.textContent = '▼';
            }} else {{
                body.style.display = 'block';
                icon.textContent = '▲';
            }}
        }}

        function setTab(tab, btn) {{
            currentTab = tab;
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            filterFindings();
        }}

        function filterFindings() {{
            const search = document.getElementById('search-input').value.toLowerCase();
            const cards = document.querySelectorAll('.finding-card');
            
            cards.forEach(card => {{
                const sev = card.getAttribute('data-severity');
                const text = card.getAttribute('data-text');

                const matchesTab = (currentTab === 'all') || 
                                   (currentTab === sev) || 
                                   (currentTab === 'medium' && (sev === 'medium' || sev === 'low'));
                const matchesSearch = text.includes(search);

                if (matchesTab && matchesSearch) {{
                    card.style.display = 'block';
                }} else {{
                    card.style.display = 'none';
                }}
            }});
        }}

        function copyFix(text, btn) {{
            navigator.clipboard.writeText(text).then(() => {{
                const originalText = btn.textContent;
                btn.textContent = 'Copied! ✓';
                setTimeout(() => {{
                    btn.textContent = originalText;
                }}, 2000);
            }});
        }}
    </script>
</body>
</html>"""

        if output_path:
            output_path.write_text(html_content, encoding="utf-8")
        return html_content
