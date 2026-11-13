"""SVG element and Bezier curve construction."""
import html as html_lib
from typing import Tuple
from secskill.graph.models import GraphLayout

def generate_svg_markup(layout: GraphLayout) -> Tuple[str, str]:
    """Generate SVG edges and node markup from precalculated layout coordinates."""
    all_nodes_dict = {}
    for n in layout.entry_nodes.values():
        all_nodes_dict[n.id] = n
    for n in layout.file_nodes.values():
        all_nodes_dict[n.id] = n
    for n in layout.sink_nodes:
        all_nodes_dict[n.id] = n
    for n in layout.target_nodes.values():
        all_nodes_dict[n.id] = n

    edges_svg_list = []
    for p in layout.attack_paths:
        idx = p.idx
        n_src = all_nodes_dict[p.src_id]
        n_file = all_nodes_dict[p.file_id]
        n_sink = all_nodes_dict[p.sink_id]
        n_target = all_nodes_dict[p.target_id]
        sev = p.severity.lower()

        # Source to File curve
        d1 = f"M {n_src.x} {n_src.y} C {n_src.x+120} {n_src.y}, {n_file.x-120} {n_file.y}, {n_file.x} {n_file.y}"
        edges_svg_list.append(f'<path d="{d1}" class="edge-line edge-input path-{idx}" onclick="selectFinding({idx})"/>')

        # File to Sink curve
        d2 = f"M {n_file.x} {n_file.y} C {n_file.x+120} {n_file.y}, {n_sink.x-120} {n_sink.y}, {n_sink.x} {n_sink.y}"
        edges_svg_list.append(f'<path d="{d2}" class="edge-line edge-flow path-{idx}" onclick="selectFinding({idx})"/>')

        # Glowing Red Jump to Database
        d3 = f"M {n_sink.x} {n_sink.y} C {n_sink.x+120} {n_sink.y}, {n_target.x-120} {n_target.y}, {n_target.x} {n_target.y}"
        glow_cls = f"edge-line edge-exploit-glow edge-{sev} path-{idx}"
        edges_svg_list.append(f'<path d="{d3}" class="{glow_cls}" onclick="selectFinding({idx})"/>')
        edges_svg_list.append(f'<path d="{d3}" class="edge-laser path-{idx}" onclick="selectFinding({idx})"/>')

    nodes_svg_list = []
    # Render Entry Nodes
    for n in layout.entry_nodes.values():
        lbl = html_lib.escape(n.label)
        nodes_svg_list.append(f'''
        <g class="node-group node-entry" transform="translate({n.x},{n.y})" onclick="highlightNode('{n.id}')">
            <circle r="26" class="node-circle circle-cyan"/>
            <svg x="-10" y="-10" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#00d2d3" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
            </svg>
            <text y="42" class="node-label">{lbl}</text>
        </g>
        ''')

    # Render File Nodes
    for n in layout.file_nodes.values():
        lbl = html_lib.escape(n.label)
        nodes_svg_list.append(f'''
        <g class="node-group node-file" transform="translate({n.x},{n.y})" onclick="highlightNode('{n.id}')">
            <circle r="27" class="node-circle circle-purple"/>
            <svg x="-10" y="-10" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#a29bfe" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                <path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/><polyline points="14 2 14 8 20 8"/>
            </svg>
            <text y="43" class="node-label">{lbl}</text>
        </g>
        ''')

    # Render Sink Nodes
    for n in layout.sink_nodes:
        lbl = html_lib.escape(n.label)
        idx = n.finding_idx
        sev = (n.severity or "medium").lower()
        stroke_color = "#ff4757" if sev == "critical" else "#ffa502"
        nodes_svg_list.append(f'''
        <g class="node-group node-sink" id="node-sink-{idx}" transform="translate({n.x},{n.y})" onclick="selectFinding({idx})">
            <circle r="29" class="node-circle circle-sink-{sev}"/>
            <svg x="-10" y="-10" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="{stroke_color}" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
            </svg>
            <text y="45" class="node-label label-sink">{lbl}</text>
        </g>
        ''')

    # Render Target Nodes (Database / Crown Jewels)
    for n in layout.target_nodes.values():
        lbl = html_lib.escape(n.label)
        nodes_svg_list.append(f'''
        <g class="node-group node-target" transform="translate({n.x},{n.y})" onclick="highlightNode('{n.id}')">
            <circle r="32" class="node-circle circle-crimson"/>
            <svg x="-11" y="-11" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#ff4d4d" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                <ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>
            </svg>
            <text y="48" class="node-label label-target">{lbl}</text>
        </g>
        ''')

    edges_svg_markup = "\n".join(edges_svg_list)
    nodes_svg_markup = "\n".join(nodes_svg_list)
    return edges_svg_markup, nodes_svg_markup

