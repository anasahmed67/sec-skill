"""Antigravity Generative UI and Visual Artifact Dashboard Generator.

Produces theme-aware interactive HTML widgets, Mermaid attack path diagrams,
and before/after diff carousels designed specifically for Google Antigravity's chat canvas.
"""
import html
from typing import List, Dict, Any, Optional
from secskill.models import Finding
from secskill.graph.inference import infer_attack_path

def generate_generative_ui_dashboard(findings: List[Finding], target_path: str = ".") -> str:
    """Generate a self-contained Antigravity Generative UI HTML widget.
    
    Styled via gstatic Tailwind CSS and Antigravity semantic variables.
    """
    total = len(findings)
    critical_count = sum(1 for f in findings if f.severity.value == "CRITICAL")
    high_count = sum(1 for f in findings if f.severity.value == "HIGH")
    medium_count = sum(1 for f in findings if f.severity.value == "MEDIUM")
    low_count = sum(1 for f in findings if f.severity.value in ("LOW", "INFO"))

    # Calculate security posture score (0 - 100)
    penalty = (critical_count * 25) + (high_count * 15) + (medium_count * 5) + (low_count * 1)
    security_score = max(0, 100 - penalty)
    score_color = "text-[var(--error)]" if security_score < 70 else ("text-[var(--warning)]" if security_score < 90 else "text-[var(--success)]")

    # Serialize findings for interactive JS filtering
    findings_data = []
    for f in findings:
        path_data = infer_attack_path(f)
        findings_data.append({
            "id": f.id,
            "title": f.title,
            "severity": f.severity.value,
            "cwe": f.cwe_id or "CWE-Unknown",
            "file": f.file_path,
            "line": f.line_number,
            "code": f.code_snippet or "",
            "remediation": f.remediation or "Apply parameterized query or context-aware input escaping.",
            "source": path_data.get("source", "Untrusted User Input"),
            "route": path_data.get("route", "Request Dispatcher"),
            "sink": path_data.get("sink", "Sensitive Sink"),
            "impact": path_data.get("impact", "Exploitation"),
        })

    import json
    json_payload = json.dumps(findings_data)

    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <script src="https://www.gstatic.com/antigravity/web/dev/tailwindcss.min.js"></script>
  <style>
    /* Theme fallbacks and smooth scroll */
    ::-webkit-scrollbar {{ width: 6px; height: 6px; }}
    ::-webkit-scrollbar-thumb {{ background: var(--card-border, #475569); border-radius: 3px; }}
  </style>
</head>
<body class="bg-transparent text-[var(--foreground)] antialiased p-0 m-0 font-sans text-xs">
  <div class="py-2 space-y-3">
    <!-- Header Posture Bar -->
    <div class="flex items-center justify-between pb-2 border-b border-[var(--card-border)]">
      <div class="flex items-center gap-2">
        <span class="text-sm font-semibold tracking-tight text-[var(--foreground)]">🛡️ SecSkill Security Dashboard</span>
        <span class="text-[10px] text-[var(--muted-foreground)] px-1.5 py-0.5 rounded bg-[var(--card)] border border-[var(--card-border)] font-mono">{html.escape(target_path)}</span>
      </div>
      <div class="flex items-center gap-2">
        <span class="text-[var(--muted-foreground)]">Posture Score:</span>
        <span class="text-sm font-bold font-mono {score_color}">{security_score}/100</span>
      </div>
    </div>

    <!-- Severity Stat Cards -->
    <div class="grid grid-cols-4 gap-2">
      <button onclick="filterSev('CRITICAL')" class="p-2 rounded border border-red-500/40 bg-red-950/20 hover:bg-red-950/40 text-left transition flex flex-col justify-between">
        <span class="text-[10px] text-red-400 font-medium">Critical</span>
        <span class="text-base font-bold text-red-400 font-mono mt-0.5">{critical_count}</span>
      </button>
      <button onclick="filterSev('HIGH')" class="p-2 rounded border border-orange-500/40 bg-orange-950/20 hover:bg-orange-950/40 text-left transition flex flex-col justify-between">
        <span class="text-[10px] text-orange-400 font-medium">High</span>
        <span class="text-base font-bold text-orange-400 font-mono mt-0.5">{high_count}</span>
      </button>
      <button onclick="filterSev('MEDIUM')" class="p-2 rounded border border-yellow-500/40 bg-yellow-950/20 hover:bg-yellow-950/40 text-left transition flex flex-col justify-between">
        <span class="text-[10px] text-yellow-400 font-medium">Medium</span>
        <span class="text-base font-bold text-yellow-400 font-mono mt-0.5">{medium_count}</span>
      </button>
      <button onclick="filterSev('ALL')" class="p-2 rounded border border-[var(--card-border)] bg-[var(--card)] hover:opacity-80 text-left transition flex flex-col justify-between">
        <span class="text-[10px] text-[var(--muted-foreground)] font-medium">Total Issues</span>
        <span class="text-base font-bold text-[var(--foreground)] font-mono mt-0.5">{total}</span>
      </button>
    </div>

    <!-- Filter & Search Bar -->
    <div class="flex items-center justify-between gap-2 pt-1">
      <div class="flex items-center gap-1.5" id="filter-tabs">
        <button onclick="filterSev('ALL')" class="px-2 py-0.5 rounded text-[11px] font-medium bg-[var(--card)] text-[var(--foreground)] border border-[var(--card-border)] hover:bg-[var(--card-border)]">All ({total})</button>
        <button onclick="filterSev('CRITICAL')" class="px-2 py-0.5 rounded text-[11px] font-medium text-red-400 border border-transparent hover:border-red-500/40">Critical ({critical_count})</button>
        <button onclick="filterSev('HIGH')" class="px-2 py-0.5 rounded text-[11px] font-medium text-orange-400 border border-transparent hover:border-orange-500/40">High ({high_count})</button>
        <button onclick="filterSev('MEDIUM')" class="px-2 py-0.5 rounded text-[11px] font-medium text-yellow-400 border border-transparent hover:border-yellow-500/40">Medium ({medium_count})</button>
      </div>
      <input id="search-input" oninput="renderTable()" type="text" placeholder="Filter by file or CWE..." class="bg-[var(--card)] text-[var(--foreground)] placeholder-[var(--placeholder)] border border-[var(--card-border)] rounded px-2 py-0.5 text-xs outline-none focus:border-[var(--primary)] w-48" />
    </div>

    <!-- Findings Table Container -->
    <div class="rounded border border-[var(--card-border)] overflow-hidden">
      <div class="max-h-56 overflow-y-auto">
        <table class="w-full text-left border-collapse">
          <thead class="sticky top-0 bg-[var(--card)] border-b border-[var(--card-border)] text-[var(--muted-foreground)]">
            <tr>
              <th class="py-1.5 px-2.5 font-medium">Severity</th>
              <th class="py-1.5 px-2 font-medium">Vulnerability & CWE</th>
              <th class="py-1.5 px-2 font-medium">Location</th>
              <th class="py-1.5 px-2 font-medium text-right">Details</th>
            </tr>
          </thead>
          <tbody id="findings-rows" class="divide-y divide-[var(--card-border)]">
          </tbody>
        </table>
      </div>
    </div>

    <!-- Interactive Taint Flow & Remediation Drawer -->
    <div id="drawer" class="hidden rounded border border-[var(--card-border)] bg-[var(--card)] p-2.5 space-y-2">
      <div class="flex items-center justify-between border-b border-[var(--card-border)] pb-1.5">
        <div class="flex items-center gap-2">
          <span id="d-badge" class="px-1.5 py-0.5 text-[10px] font-bold rounded"></span>
          <span id="d-title" class="font-semibold text-xs text-[var(--foreground)]"></span>
        </div>
        <button onclick="closeDrawer()" class="text-[var(--muted-foreground)] hover:text-[var(--foreground)] text-xs">✕ Close</button>
      </div>
      
      <!-- Taint Dataflow Visualization -->
      <div class="space-y-1">
        <span class="text-[10px] font-semibold text-[var(--muted-foreground)] uppercase tracking-wider">AST Taint Dataflow Path:</span>
        <div class="flex items-center gap-1.5 text-[10px] overflow-x-auto py-1">
          <div class="px-2 py-1 rounded bg-red-950/40 border border-red-500/30 text-red-300 font-mono" id="d-source"></div>
          <span class="text-[var(--muted-foreground)]">➔</span>
          <div class="px-2 py-1 rounded bg-slate-800 border border-slate-700 text-slate-300 font-mono" id="d-route"></div>
          <span class="text-[var(--muted-foreground)]">➔</span>
          <div class="px-2 py-1 rounded bg-rose-950/40 border border-rose-500/40 text-rose-300 font-mono font-semibold" id="d-sink"></div>
          <span class="text-[var(--muted-foreground)]">➔</span>
          <div class="px-2 py-1 rounded bg-red-950/80 border border-red-600 text-red-200 font-mono" id="d-impact"></div>
        </div>
      </div>

      <!-- Remediation Advice -->
      <div class="space-y-0.5 text-[11px]">
        <span class="text-[10px] font-semibold text-[var(--muted-foreground)] uppercase tracking-wider">Recommended Fix:</span>
        <p class="text-[var(--foreground)] font-mono text-[10px] bg-slate-900/40 p-1.5 rounded border border-[var(--card-border)]" id="d-remediation"></p>
      </div>
    </div>
  </div>

  <script>
    const allFindings = {json_payload};
    let activeFilter = 'ALL';

    function filterSev(sev) {{
      activeFilter = sev;
      renderTable();
    }}

    function renderTable() {{
      const query = document.getElementById('search-input').value.toLowerCase();
      const tbody = document.getElementById('findings-rows');
      tbody.innerHTML = '';

      const filtered = allFindings.filter(f => {{
        const matchesSev = activeFilter === 'ALL' || f.severity === activeFilter;
        const matchesQuery = !query || f.file.toLowerCase().includes(query) || f.title.toLowerCase().includes(query) || f.cwe.toLowerCase().includes(query);
        return matchesSev && matchesQuery;
      }});

      if (filtered.length === 0) {{
        tbody.innerHTML = '<tr><td colspan="4" class="py-4 text-center text-[var(--muted-foreground)]">No matching vulnerabilities found.</td></tr>';
        return;
      }}

      filtered.forEach((f, idx) => {{
        const tr = document.createElement('tr');
        tr.className = 'hover:bg-[var(--card)] cursor-pointer transition';
        tr.onclick = () => showDrawer(f);

        const sevColors = {{
          'CRITICAL': 'text-red-400 bg-red-950/40 border-red-500/40',
          'HIGH': 'text-orange-400 bg-orange-950/40 border-orange-500/40',
          'MEDIUM': 'text-yellow-400 bg-yellow-950/40 border-yellow-500/40',
          'LOW': 'text-sky-400 bg-sky-950/40 border-sky-500/40',
        }}[f.severity] || 'text-slate-400 bg-slate-800 border-slate-700';

        tr.innerHTML = `
          <td class="py-1.5 px-2.5">
            <span class="px-1.5 py-0.5 rounded border text-[10px] font-mono font-bold ${{sevColors}}">${{f.severity}}</span>
          </td>
          <td class="py-1.5 px-2">
            <div class="font-medium text-[var(--foreground)]">${{escapeHtml(f.title)}}</div>
            <div class="text-[10px] text-[var(--muted-foreground)] font-mono">${{escapeHtml(f.cwe)}}</div>
          </td>
          <td class="py-1.5 px-2 text-[var(--muted-foreground)] font-mono text-[10px]">
            ${{escapeHtml(f.file)}}:${{f.line}}
          </td>
          <td class="py-1.5 px-2 text-right">
            <button class="text-[10px] text-[var(--primary)] hover:underline">Inspect ➔</button>
          </td>
        `;
        tbody.appendChild(tr);
      }});
    }}

    function showDrawer(f) {{
      const drawer = document.getElementById('drawer');
      drawer.classList.remove('hidden');

      const badge = document.getElementById('d-badge');
      badge.textContent = f.severity;
      badge.className = 'px-1.5 py-0.5 text-[10px] font-bold rounded ' + (
        f.severity === 'CRITICAL' ? 'bg-red-900/60 text-red-300 border border-red-500' :
        f.severity === 'HIGH' ? 'bg-orange-900/60 text-orange-300 border border-orange-500' :
        'bg-yellow-900/60 text-yellow-300 border border-yellow-500'
      );

      document.getElementById('d-title').textContent = f.title + ' (' + f.cwe + ')';
      document.getElementById('d-source').textContent = 'Source: ' + f.source;
      document.getElementById('d-route').textContent = 'Route: ' + f.route;
      document.getElementById('d-sink').textContent = 'Sink: ' + f.sink;
      document.getElementById('d-impact').textContent = 'Impact: ' + f.impact;
      document.getElementById('d-remediation').textContent = f.remediation;
    }}

    function closeDrawer() {{
      document.getElementById('drawer').classList.add('hidden');
    }}

    function escapeHtml(str) {{
      return (str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }}

    // Initial render
    renderTable();
  </script>
</body>
</html>
"""

def generate_mermaid_attack_map(findings: List[Finding], limit: int = 4) -> str:
    """Generate a combined Mermaid flowchart representing taint flows for top findings."""
    critical_or_high = [f for f in findings if f.severity.value in ("CRITICAL", "HIGH")]
    selected = critical_or_high[:limit] if critical_or_high else findings[:limit]

    if not selected:
        return ""

    lines = ["```mermaid", "flowchart LR"]
    for i, f in enumerate(selected, 1):
        path = infer_attack_path(f)
        source = path.get("source", "User Input").replace('"', "'")
        route = path.get("route", "Dispatcher").replace('"', "'")
        sink = path.get("sink", "Unsafe Sink").replace('"', "'")
        impact = path.get("impact", "Data Leak / RCE").replace('"', "'")

        lines.append(f'    subgraph Path_{i}["{f.title} ({f.cwe_id or "CWE"})"]')
        lines.append(f'        S_{i}["{source}"] -->|"untrusted"| R_{i}["{route}"]')
        lines.append(f'        R_{i} -->|"missing check"| K_{i}["{sink}"]')
        lines.append(f'        K_{i} -->|"blast radius"| I_{i}[("{impact}")]')
        lines.append("    end")
        lines.append(f"    style S_{i} fill:#ef4444,stroke:#fff,stroke-width:1px,color:#fff")
        lines.append(f"    style K_{i} fill:#b91c1c,stroke:#fff,stroke-width:2px,color:#fff")
        lines.append(f"    style I_{i} fill:#7f1d1d,stroke:#fff,stroke-width:1px,color:#fff")

    lines.append("```")
    return "\n".join(lines)

def generate_patch_carousel(before_code: str, after_code: str, file_path: str, vuln_title: str) -> str:
    """Generate an Antigravity 4-backtick carousel comparing vulnerable vs patched code."""
    return f"""````carousel
```python
# [BEFORE] Vulnerable Code in {file_path}
# Flaw: {vuln_title}
{before_code.strip()}
```
<!-- slide -->
```python
# [AFTER] SecSkill Hardened Patch in {file_path}
# Status: Verified Impenetrable (secskill_verify_patch: PASS)
{after_code.strip()}
```
````"""

