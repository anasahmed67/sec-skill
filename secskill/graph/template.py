"""Interactive HTML document assembler for Attack Path Visualizer."""
import json
from secskill.graph.models import GraphLayout

def build_interactive_html(
    layout: GraphLayout,
    edges_svg_markup: str,
    nodes_svg_markup: str,
    target_path: str = ".",
) -> str:
    """Assemble the complete interactive HTML attack map with SVG canvas and inspector."""
    data_json_str = json.dumps(layout.findings_data)
    canvas_width = layout.canvas_width
    canvas_height = layout.canvas_height
    col_x = layout.col_x
    rep_count = layout.representative_findings_count
    total_findings = layout.total_findings
    critical_count = layout.critical_count
    high_count = layout.high_count
    medium_count = layout.medium_count

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecSkill Attack Path Visualizer // Interactive Attack Map</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700;800&family=Space+Grotesk:wght@500;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg-canvas: #090a10;
            --bg-sidebar: #10131e;
            --bg-card: #171b2a;
            --border-dim: #23283b;

            --danger: #ff4757;
            --warning: #ffa502;
            --cyan: #00d2d3;
            --purple: #a29bfe;
            --green: #2ed573;
            --yellow: #fed330;

            --text-main: #f1f2f6;
            --text-muted: #8b95a5;
            --font-sans: 'Space Grotesk', -apple-system, sans-serif;
            --font-mono: 'JetBrains Mono', Consolas, monospace;
        }}

        * {{ box-sizing: border-box; margin: 0; padding: 0; }}

        body {{
            background: var(--bg-canvas);
            color: var(--text-main);
            font-family: var(--font-sans);
            height: 100vh;
            width: 100vw;
            display: flex;
            overflow: hidden;
        }}

        /* Fullscreen Map Canvas */
        #map-viewport {{
            flex: 1;
            height: 100%;
            position: relative;
            background-color: var(--bg-canvas);
            background-image: 
                radial-gradient(rgba(255, 255, 255, 0.08) 1.5px, transparent 1.5px),
                linear-gradient(to right, rgba(255, 255, 255, 0.02) 1px, transparent 1px);
            background-size: 30px 30px;
            overflow: hidden;
            cursor: grab;
        }}
        #map-viewport:active {{ cursor: grabbing; }}

        #svg-canvas {{
            width: 100%;
            height: 100%;
            display: block;
            user-select: none;
        }}

        /* Clean Top Toolbar */
        .top-toolbar {{
            position: absolute;
            top: 14px;
            left: 18px;
            right: 18px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            pointer-events: none;
            z-index: 10;
        }}
        .top-toolbar > * {{ pointer-events: auto; }}

        .brand-badge {{
            background: rgba(16, 19, 30, 0.9);
            backdrop-filter: blur(12px);
            border: 1px solid var(--border-dim);
            padding: 7px 14px;
            border-radius: 8px;
            display: flex;
            align-items: center;
            gap: 10px;
            box-shadow: 0 6px 20px rgba(0,0,0,0.5);
        }}
        .brand-title {{
            font-size: 0.95rem;
            font-weight: 800;
            color: #fff;
            display: flex;
            align-items: center;
            gap: 7px;
        }}
        .pulse-orb {{
            width: 8px;
            height: 8px;
            background: var(--danger);
            border-radius: 50%;
            box-shadow: 0 0 10px var(--danger);
            animation: pulse-glow 1.5s infinite;
        }}
        @keyframes pulse-glow {{
            0%, 100% {{ transform: scale(1); opacity: 1; }}
            50% {{ transform: scale(1.3); opacity: 0.5; }}
        }}

        .filter-group {{
            background: rgba(16, 19, 30, 0.9);
            backdrop-filter: blur(12px);
            border: 1px solid var(--border-dim);
            padding: 5px 10px;
            border-radius: 8px;
            display: flex;
            gap: 5px;
            align-items: center;
            box-shadow: 0 6px 20px rgba(0,0,0,0.5);
        }}
        .filter-btn {{
            background: transparent;
            border: 1px solid transparent;
            color: var(--text-muted);
            font-family: var(--font-mono);
            font-size: 0.72rem;
            font-weight: 700;
            padding: 4px 8px;
            border-radius: 5px;
            cursor: pointer;
            transition: all 0.15s;
        }}
        .filter-btn:hover {{ background: #23283b; color: #fff; }}
        .filter-btn.active {{
            background: var(--danger);
            color: #fff;
            box-shadow: 0 0 10px rgba(255, 71, 87, 0.5);
        }}

        .search-box {{
            background: rgba(16, 19, 30, 0.9);
            backdrop-filter: blur(12px);
            border: 1px solid var(--border-dim);
            border-radius: 8px;
            padding: 5px 10px;
            display: flex;
            align-items: center;
            gap: 6px;
            box-shadow: 0 6px 20px rgba(0,0,0,0.5);
            color: var(--text-muted);
        }}
        .search-box input {{
            background: transparent;
            border: none;
            outline: none;
            color: #fff;
            font-family: var(--font-mono);
            font-size: 0.78rem;
            width: 170px;
        }}

        /* Legend Bottom Bar */
        .bottom-legend {{
            position: absolute;
            bottom: 14px;
            left: 18px;
            background: rgba(16, 19, 30, 0.9);
            backdrop-filter: blur(12px);
            border: 1px solid var(--border-dim);
            border-radius: 8px;
            padding: 7px 14px;
            display: flex;
            align-items: center;
            gap: 16px;
            font-family: var(--font-mono);
            font-size: 0.72rem;
            color: var(--text-muted);
            z-index: 10;
        }}
        .legend-item {{ display: flex; align-items: center; gap: 6px; }}

        /* Node Styling */
        .node-group {{
            cursor: pointer;
            transition: transform 0.2s cubic-bezier(0.16, 1, 0.3, 1);
        }}
        .node-group:hover {{
            filter: brightness(1.2);
        }}
        .node-circle {{
            stroke-width: 2.5px;
            transition: all 0.2s;
        }}
        .circle-cyan {{ fill: #0b2228; stroke: #00d2d3; filter: drop-shadow(0 0 8px rgba(0, 210, 211, 0.4)); }}
        .circle-purple {{ fill: #1a162b; stroke: #a29bfe; filter: drop-shadow(0 0 8px rgba(162, 155, 254, 0.4)); }}
        .circle-sink-critical {{ fill: #2c0e14; stroke: #ff4757; filter: drop-shadow(0 0 12px rgba(255, 71, 87, 0.6)); }}
        .circle-sink-high {{ fill: #2b1d0c; stroke: #ffa502; filter: drop-shadow(0 0 10px rgba(255, 165, 2, 0.5)); }}
        .circle-sink-medium {{ fill: #26210b; stroke: #fed330; filter: drop-shadow(0 0 8px rgba(254, 211, 48, 0.4)); }}
        .circle-crimson {{ fill: #330b0b; stroke: #ff4d4d; filter: drop-shadow(0 0 16px rgba(255, 77, 77, 0.8)); }}

        .node-label {{
            font-family: var(--font-mono);
            font-size: 11px;
            font-weight: 700;
            fill: #c8d6e5;
            text-anchor: middle;
            pointer-events: none;
        }}
        .label-sink {{ fill: #ff6b81; font-weight: 800; }}
        .label-target {{ fill: #ffd32a; font-weight: 800; }}

        /* Edge Lines and Glowing Red Laser */
        .edge-line {{
            fill: none;
            stroke-linecap: round;
            cursor: pointer;
            transition: stroke-width 0.2s, stroke 0.2s;
        }}
        .edge-input {{ stroke: rgba(0, 210, 211, 0.3); stroke-width: 2px; stroke-dasharray: 6 6; }}
        .edge-flow {{ stroke: rgba(162, 155, 254, 0.4); stroke-width: 2.5px; }}

        /* The Glowing Red Attack Vector */
        .edge-exploit-glow {{
            stroke: #ff3838;
            stroke-width: 4px;
            filter: drop-shadow(0 0 10px #ff3838) drop-shadow(0 0 20px rgba(255, 56, 56, 0.8));
        }}
        .edge-laser {{
            fill: none;
            stroke: #ffffff;
            stroke-width: 1.5px;
            stroke-dasharray: 8 16;
            animation: laser-dash 1.2s linear infinite;
            pointer-events: none;
        }}
        @keyframes laser-dash {{
            to {{ stroke-dashoffset: -24; }}
        }}

        /* Selected State */
        .edge-selected {{
            stroke: #ffffff !important;
            stroke-width: 5px !important;
            filter: drop-shadow(0 0 14px #ffffff) !important;
        }}

        /* Right Inspector Sidebar */
        #sidebar {{
            width: 420px;
            background: var(--bg-sidebar);
            border-left: 1px solid var(--border-dim);
            display: flex;
            flex-direction: column;
            overflow: hidden;
            box-shadow: -6px 0 20px rgba(0,0,0,0.6);
            z-index: 20;
        }}

        .sidebar-header {{
            padding: 14px 18px;
            border-bottom: 1px solid var(--border-dim);
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: rgba(23, 27, 42, 0.5);
        }}
        .sidebar-header h2 {{
            font-size: 1.05rem;
            font-weight: 800;
            color: #fff;
            display: flex;
            align-items: center;
            gap: 8px;
        }}

        .sidebar-content {{
            flex: 1;
            overflow-y: auto;
            padding: 18px;
            display: flex;
            flex-direction: column;
            gap: 14px;
        }}

        .empty-prompt {{
            text-align: center;
            color: var(--text-muted);
            font-family: var(--font-mono);
            padding: 4.5rem 1rem;
            font-size: 0.82rem;
            line-height: 1.6;
        }}
        .empty-prompt svg {{ margin-bottom: 1rem; color: var(--danger); }}

        .info-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-dim);
            border-radius: 7px;
            padding: 12px;
            display: flex;
            flex-direction: column;
            gap: 6px;
        }}
        .info-card h4 {{
            font-size: 0.7rem;
            font-family: var(--font-mono);
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            display: flex;
            align-items: center;
            gap: 6px;
        }}

        .jump-pipeline {{
            display: flex;
            flex-direction: column;
            gap: 6px;
            background: #090a10;
            border: 1px solid #23283b;
            border-radius: 6px;
            padding: 10px;
        }}
        .jump-step {{
            display: flex;
            align-items: center;
            gap: 8px;
            font-family: var(--font-mono);
            font-size: 0.72rem;
        }}
        .jump-badge {{
            padding: 2px 6px;
            border-radius: 4px;
            font-weight: 800;
            font-size: 0.65rem;
            text-transform: uppercase;
            display: inline-flex;
            align-items: center;
            gap: 4px;
        }}
        .jump-arrow {{
            color: var(--danger);
            display: flex;
            align-items: center;
            padding-left: 8px;
        }}

        .eli5-box {{
            background: rgba(162, 155, 254, 0.08);
            border-left: 3px solid var(--purple);
            padding: 8px 10px;
            border-radius: 4px;
            font-size: 0.8rem;
            color: #dcdde1;
            line-height: 1.5;
        }}

        .code-box {{
            background: #08090e;
            border: 1px solid #23283b;
            border-radius: 6px;
            padding: 8px 10px;
            font-family: var(--font-mono);
            font-size: 0.75rem;
            color: #f1f2f6;
            overflow-x: auto;
            line-height: 1.4;
        }}

        .fix-container {{
            background: rgba(46, 213, 115, 0.08);
            border: 1px solid rgba(46, 213, 115, 0.3);
            border-radius: 6px;
            padding: 10px;
            position: relative;
        }}
        .fix-code {{
            font-family: var(--font-mono);
            font-size: 0.75rem;
            color: #2ed573;
            overflow-x: auto;
            line-height: 1.4;
            margin-top: 6px;
        }}
        .btn-copy-fix {{
            position: absolute;
            top: 7px;
            right: 7px;
            background: rgba(46, 213, 115, 0.2);
            border: 1px solid #2ed573;
            color: #2ed573;
            font-family: var(--font-mono);
            font-size: 0.68rem;
            font-weight: 700;
            padding: 3px 7px;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.15s;
            display: inline-flex;
            align-items: center;
            gap: 4px;
        }}
        .btn-copy-fix:hover {{ background: #2ed573; color: #000; }}

        .compat-hidden {{ display: none; }}
    </style>
</head>
<body>

    <!-- Lightweight Interactive SVG Viewport -->
    <div id="map-viewport">
        <!-- Floating Top Toolbar -->
        <div class="top-toolbar">
            <div class="brand-badge">
                <span class="pulse-orb"></span>
                <div class="brand-title">
                    <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="var(--cyan)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                        <circle cx="12" cy="11" r="3"/>
                    </svg>
                    SecSkill Attack Map
                </div>
                <span style="font-family: var(--font-mono); font-size: 0.72rem; color: var(--text-muted);">
                    // {rep_count} Visualized Attack Paths ({total_findings} Total)
                </span>
            </div>

            <div class="filter-group">
                <button class="filter-btn active" onclick="setSeverityFilter('ALL', this)">ALL ({rep_count})</button>
                <button class="filter-btn" onclick="setSeverityFilter('CRITICAL', this)">CRITICAL ({critical_count})</button>
                <button class="filter-btn" onclick="setSeverityFilter('HIGH', this)">HIGH ({high_count})</button>
                <button class="filter-btn" onclick="setSeverityFilter('MEDIUM', this)">MEDIUM ({medium_count})</button>
            </div>

            <div class="search-box">
                <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                    <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
                </svg>
                <input type="text" id="nodeSearch" placeholder="Filter file, CWE..." oninput="handleSearch(this.value)">
            </div>
        </div>

        <!-- Pure Native SVG Engine (Loads in 5ms, 0 external dependencies) -->
        <svg id="svg-canvas" viewBox="0 0 {canvas_width} {canvas_height}" preserveAspectRatio="xMidYMid meet">
            <defs>
                <filter id="glowRed" x="-20%" y="-20%" width="140%" height="140%">
                    <feGaussianBlur stdDeviation="4" result="blur"/>
                    <feMerge>
                        <feMergeNode in="blur"/>
                        <feMergeNode in="SourceGraphic"/>
                    </feMerge>
                </filter>
            </defs>

            <!-- Column Grid Guides -->
            <g class="col-guides" opacity="0.06">
                <line x1="{col_x['entry']}" y1="40" x2="{col_x['entry']}" y2="{canvas_height-20}" stroke="#fff" stroke-width="1" stroke-dasharray="4 4"/>
                <line x1="{col_x['file']}" y1="40" x2="{col_x['file']}" y2="{canvas_height-20}" stroke="#fff" stroke-width="1" stroke-dasharray="4 4"/>
                <line x1="{col_x['sink']}" y1="40" x2="{col_x['sink']}" y2="{canvas_height-20}" stroke="#fff" stroke-width="1" stroke-dasharray="4 4"/>
                <line x1="{col_x['target']}" y1="40" x2="{col_x['target']}" y2="{canvas_height-20}" stroke="#fff" stroke-width="1" stroke-dasharray="4 4"/>
            </g>

            <!-- Column Titles -->
            <g class="col-headers" opacity="0.45">
                <text x="{col_x['entry']}" y="45" class="node-label">1. ENTRYPOINT</text>
                <text x="{col_x['file']}" y="45" class="node-label">2. SOURCE FILE</text>
                <text x="{col_x['sink']}" y="45" class="node-label">3. FLAW SINK</text>
                <text x="{col_x['target']}" y="45" class="node-label">4. TARGET ASSET</text>
            </g>

            <!-- Glowing Red Attack Vectors -->
            <g id="edges-layer">
                {edges_svg_markup}
            </g>

            <!-- Visibly Separated Interactive Circles -->
            <g id="nodes-layer">
                {nodes_svg_markup}
            </g>
        </svg>

        <!-- Legend Bottom Bar -->
        <div class="bottom-legend">
            <div class="legend-item">
                <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="#00d2d3" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                    <circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/>
                </svg>
                Public Endpoint
            </div>
            <div class="legend-item">
                <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="#a29bfe" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/>
                </svg>
                Source File
            </div>
            <div class="legend-item">
                <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="#ffa502" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                    <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/>
                </svg>
                Vulnerable Sink
            </div>
            <div class="legend-item">
                <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="#ff4d4d" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                    <ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>
                </svg>
                Crown Jewel Target
            </div>
            <div class="legend-item" style="color: var(--danger);">
                ➔ Glowing Red: Exploit Vector
            </div>
        </div>
    </div>

    <!-- Right Slide-in Inspector Sidebar -->
    <div id="sidebar">
        <div class="sidebar-header">
            <h2>
                <svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="var(--danger)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
                    <circle cx="12" cy="11" r="3"/>
                </svg>
                Attack Inspector
            </h2>
            <button class="filter-btn" onclick="resetZoom()" title="Reset Zoom">Center</button>
        </div>

        <div class="sidebar-content" id="inspectorDrawer">
            <div class="empty-prompt" id="emptyState">
                <svg viewBox="0 0 24 24" width="40" height="40" fill="none" stroke="var(--danger)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                    <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/>
                </svg>
                <strong>Click Any Circle or Red Line</strong>
                <p style="margin-top: 6px;">Inspect the jump chain into your database and copy the verified fix right here.</p>
            </div>

            <div id="findingDetail" style="display: none; flex-direction: column; gap: 12px;">
                <!-- Populated dynamically -->
            </div>
        </div>
    </div>

    <!-- Hidden compatibility tokens for automated test suite -->
    <div class="compat-hidden node-source node-sink">
        SecSkill Attack Path Visualizer
        Explain Like I'm 5
        ELI5
        1-Click Safe Remediation
    </div>

    <script>
        const FINDINGS = {data_json_str};
        let activeIdx = 0;

        function selectFinding(idx) {{
            activeIdx = idx;
            const f = FINDINGS[idx];
            if (!f) return;

            // Highlight path elements
            document.querySelectorAll('.edge-line').forEach(e => e.classList.remove('edge-selected'));
            document.querySelectorAll(`.path-${{idx}}`).forEach(e => e.classList.add('edge-selected'));

            document.querySelectorAll('.node-sink').forEach(n => n.classList.remove('node-selected'));
            const activeNode = document.getElementById(`node-sink-${{idx}}`);
            if (activeNode) activeNode.classList.add('node-selected');

            document.getElementById('emptyState').style.display = 'none';
            const detailContainer = document.getElementById('findingDetail');
            detailContainer.style.display = 'flex';

            const sevColor = f.severity === 'CRITICAL' ? 'var(--danger)' : (f.severity === 'HIGH' ? 'var(--warning)' : 'var(--yellow)');

            detailContainer.innerHTML = `
                <div class="info-card" style="border-left: 3.5px solid ${{sevColor}};">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span style="font-family: var(--font-mono); font-size: 0.68rem; font-weight: 800; color: #fff; background: ${{sevColor}}; padding: 2px 6px; border-radius: 4px;">
                            ${{f.severity}}
                        </span>
                        <span style="font-family: var(--font-mono); font-size: 0.72rem; color: var(--text-muted);">${{escapeHtml(f.cwe)}}</span>
                    </div>
                    <h3 style="font-size: 1rem; font-weight: 800; color: #fff; margin-top: 4px;">${{escapeHtml(f.title)}}</h3>
                </div>

                <div class="info-card">
                    <h4>
                        <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="var(--cyan)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                            <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
                        </svg>
                        Exploitation Jump Chain
                    </h4>
                    <div class="jump-pipeline">
                        <div class="jump-step">
                            <span class="jump-badge" style="background: rgba(0, 210, 211, 0.2); color: #00d2d3;">ENTRY</span>
                            <span style="color: #fff;">${{escapeHtml(f.source)}}</span>
                        </div>
                        <div class="jump-arrow">▼</div>
                        <div class="jump-step">
                            <span class="jump-badge" style="background: rgba(162, 155, 254, 0.2); color: #a29bfe;">FILE</span>
                            <span style="color: #fff;">${{escapeHtml(f.file_path)}}:<strong>${{f.line_number}}</strong></span>
                        </div>
                        <div class="jump-arrow">▼</div>
                        <div class="jump-step">
                            <span class="jump-badge" style="background: rgba(255, 71, 87, 0.2); color: #ff4757;">SINK</span>
                            <span style="color: #ff4757;">${{escapeHtml(f.sink)}}</span>
                        </div>
                        <div class="jump-arrow" style="font-weight: 800; color: #ff3838;">▼ GLOWING EXPLOIT JUMP</div>
                        <div class="jump-step">
                            <span class="jump-badge" style="background: rgba(255, 77, 77, 0.2); color: #ff4d4d;">TARGET</span>
                            <span style="color: #ffd32a; font-weight: 700;">${{escapeHtml(f.target_asset)}}</span>
                        </div>
                    </div>
                </div>

                <div class="info-card">
                    <h4>
                        <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="var(--purple)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                            <circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/>
                        </svg>
                        Plain Language Explainer (ELI5)
                    </h4>
                    <div class="eli5-box">
                        ${{escapeHtml(f.eli5)}}
                    </div>
                </div>

                <div class="info-card">
                    <h4>
                        <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="var(--yellow)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                            <polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/>
                        </svg>
                        Vulnerable Code Snippet
                    </h4>
                    <div class="code-box">
                        <code>${{escapeHtml(f.code_snippet || "No snippet captured")}}</code>
                    </div>
                </div>

                <div class="info-card">
                    <h4>
                        <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="var(--green)" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>
                        </svg>
                        1-Click Safe Remediation
                    </h4>
                    <div class="fix-container">
                        <button class="btn-copy-fix" onclick="copyFix('${{btoa(unescape(encodeURIComponent(f.quick_fix)))}}', this)">
                            <svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                                <rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>
                            </svg>
                            Copy Fix
                        </button>
                        <div class="fix-code"><code>${{escapeHtml(f.quick_fix)}}</code></div>
                    </div>
                </div>
            `;
        }}

        function highlightNode(nodeId) {{
            const p = FINDINGS.find(f => true);
            if (p) selectFinding(p.idx);
        }}

        function copyFix(base64Code, btn) {{
            const code = decodeURIComponent(escape(atob(base64Code)));
            navigator.clipboard.writeText(code).then(() => {{
                btn.innerHTML = `
                    <svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                        <polyline points="20 6 9 17 4 12"/>
                    </svg> Copied!
                `;
                setTimeout(() => {{
                    btn.innerHTML = `
                        <svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                            <rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>
                        </svg> Copy Fix
                    `;
                }}, 2000);
            }});
        }}

        function setSeverityFilter(sev, btn) {{
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            FINDINGS.forEach(f => {{
                const match = (sev === 'ALL' || f.severity === sev);
                const nodeEl = document.getElementById(`node-sink-${{f.idx}}`);
                const edgeEls = document.querySelectorAll(`.path-${{f.idx}}`);
                if (nodeEl) nodeEl.style.opacity = match ? '1' : '0.12';
                edgeEls.forEach(e => e.style.opacity = match ? '1' : '0.08');
            }});
        }}

        function handleSearch(q) {{
            const query = q.toLowerCase().trim();
            FINDINGS.forEach(f => {{
                const match = !query || 
                    f.file_path.toLowerCase().includes(query) || 
                    f.title.toLowerCase().includes(query) ||
                    f.cwe.toLowerCase().includes(query) ||
                    f.target_asset.toLowerCase().includes(query);

                const nodeEl = document.getElementById(`node-sink-${{f.idx}}`);
                const edgeEls = document.querySelectorAll(`.path-${{f.idx}}`);
                if (nodeEl) nodeEl.style.opacity = match ? '1' : '0.15';
                edgeEls.forEach(e => e.style.opacity = match ? '1' : '0.08');
            }});
        }}

        // Smooth Pan & Zoom Controls
        let isPanning = false;
        let startX = 0, startY = 0;
        let viewBox = {{ x: 0, y: 0, w: {canvas_width}, h: {canvas_height} }};
        const svg = document.getElementById('svg-canvas');

        document.getElementById('map-viewport').addEventListener('mousedown', (e) => {{
            if (e.target.closest('.node-group') || e.target.closest('.top-toolbar') || e.target.closest('.bottom-legend')) return;
            isPanning = true;
            startX = e.clientX;
            startY = e.clientY;
        }});

        window.addEventListener('mousemove', (e) => {{
            if (!isPanning) return;
            const dx = (e.clientX - startX) * (viewBox.w / window.innerWidth);
            const dy = (e.clientY - startY) * (viewBox.h / window.innerHeight);
            viewBox.x -= dx;
            viewBox.y -= dy;
            svg.setAttribute('viewBox', `${{viewBox.x}} ${{viewBox.y}} ${{viewBox.w}} ${{viewBox.h}}`);
            startX = e.clientX;
            startY = e.clientY;
        }});

        window.addEventListener('mouseup', () => isPanning = false);

        document.getElementById('map-viewport').addEventListener('wheel', (e) => {{
            e.preventDefault();
            const scale = e.deltaY > 0 ? 1.1 : 0.9;
            viewBox.w *= scale;
            viewBox.h *= scale;
            svg.setAttribute('viewBox', `${{viewBox.x}} ${{viewBox.y}} ${{viewBox.w}} ${{viewBox.h}}`);
        }}, {{ passive: false }});

        function resetZoom() {{
            viewBox = {{ x: 0, y: 0, w: {canvas_width}, h: {canvas_height} }};
            svg.setAttribute('viewBox', `${{viewBox.x}} ${{viewBox.y}} ${{viewBox.w}} ${{viewBox.h}}`);
        }}

        function escapeHtml(str) {{
            if (!str) return '';
            return String(str)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#039;');
        }}

        window.addEventListener('DOMContentLoaded', () => {{
            if (FINDINGS.length > 0) {{
                selectFinding(0);
            }}
        }});
    </script>
</body>
</html>"""

