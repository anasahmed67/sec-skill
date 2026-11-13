"""Graph topology modeling and coordinate geometry calculation engine."""
from typing import List, Dict, Any
from secskill.models import Finding
from secskill.graph.models import GraphNode, GraphEdge, GraphLayout
from secskill.graph.inference import infer_attack_path

def calculate_graph_layout(
    findings: List[Finding],
    canvas_width: int = 1150,
    max_representative: int = 20,
) -> GraphLayout:
    """Filter findings and compute balanced 2D coordinates across a 4-tier DAG."""
    sev_rank = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0, "INFO": 0}

    sorted_findings = sorted(
        findings,
        key=lambda f: (sev_rank.get(f.severity.value, 0), f.line_number),
        reverse=True
    )

    seen_keys = set()
    representative_findings: List[Finding] = []
    for f in sorted_findings:
        key = (f.file_path, f.rule_id)
        if key not in seen_keys:
            seen_keys.add(key)
            representative_findings.append(f)
        if len(representative_findings) >= max_representative:
            break

    if not representative_findings and sorted_findings:
        representative_findings = sorted_findings[:max_representative]

    entry_nodes: Dict[str, GraphNode] = {}
    file_nodes: Dict[str, GraphNode] = {}
    sink_nodes: List[GraphNode] = []
    target_nodes: Dict[str, GraphNode] = {}
    attack_paths: List[GraphEdge] = []
    findings_data: List[Dict[str, Any]] = []

    for idx, f in enumerate(representative_findings):
        path_data = infer_attack_path(f)
        sev = f.severity.value
        cwe = f.cwe_id or "CWE-General"

        finding_obj = {
            "idx": idx,
            "id": f.id,
            "title": f.title,
            "severity": sev,
            "cwe": cwe,
            "owasp": f.owasp_category or "Security Flaw",
            "file_path": f.file_path,
            "line_number": f.line_number,
            "code_snippet": f.code_snippet or "",
            "source": path_data["source"],
            "source_type": path_data["source_type"],
            "route": path_data["route"],
            "flaw": path_data["flaw"],
            "sink": path_data["sink"],
            "impact": path_data["impact"],
            "target_asset": path_data.get("target_asset", "Target System"),
            "target_type": path_data.get("target_type", "System"),
            "eli5": path_data.get("eli5", "An unvalidated input path reaches a critical execution sink."),
            "quick_fix": path_data.get("quick_fix", "# Sanitize and validate input before processing"),
        }
        findings_data.append(finding_obj)

        src_key = path_data["source_type"]
        if src_key not in entry_nodes:
            entry_nodes[src_key] = GraphNode(
                id=f"src_{len(entry_nodes)}",
                label=src_key,
                sub=path_data["source"],
                col="entry"
            )

        file_key = f.file_path.split("/")[-1].split("\\")[-1]
        if f.file_path not in file_nodes:
            file_nodes[f.file_path] = GraphNode(
                id=f"file_{len(file_nodes)}",
                label=file_key,
                sub=f.file_path,
                col="file"
            )

        target_key = path_data.get("target_asset", "Database")
        if target_key not in target_nodes:
            target_nodes[target_key] = GraphNode(
                id=f"target_{len(target_nodes)}",
                label=target_key,
                sub=path_data.get("impact", "Data compromise"),
                col="target"
            )

        sink_id = f"sink_{idx}"
        sink_nodes.append(GraphNode(
            id=sink_id,
            label=f"Line {f.line_number}: {cwe}",
            sub=f.title,
            col="sink",
            severity=sev,
            finding_idx=idx
        ))

        attack_paths.append(GraphEdge(
            idx=idx,
            src_id=entry_nodes[src_key].id,
            file_id=file_nodes[f.file_path].id,
            sink_id=sink_id,
            target_id=target_nodes[target_key].id,
            severity=sev
        ))

    col_x = {
        "entry": 110,
        "file": 390,
        "sink": 680,
        "target": 980
    }

    max_rows = max(len(entry_nodes), len(file_nodes), len(sink_nodes), len(target_nodes), 1)
    row_height = 110
    canvas_height = max(700, max_rows * row_height + 120)

    def assign_y(items: List[GraphNode], total_h: int) -> None:
        count = len(items)
        spacing = (total_h - 140) / max(count, 1)
        for i, item in enumerate(items):
            item.x = col_x[item.col]
            item.y = 90 + i * spacing + (spacing / 2)

    assign_y(list(entry_nodes.values()), canvas_height)
    assign_y(list(file_nodes.values()), canvas_height)
    assign_y(sink_nodes, canvas_height)
    assign_y(list(target_nodes.values()), canvas_height)

    return GraphLayout(
        entry_nodes=entry_nodes,
        file_nodes=file_nodes,
        sink_nodes=sink_nodes,
        target_nodes=target_nodes,
        attack_paths=attack_paths,
        findings_data=findings_data,
        representative_findings_count=len(representative_findings),
        canvas_width=canvas_width,
        canvas_height=canvas_height,
        total_findings=len(findings),
        critical_count=sum(1 for f in findings if f.severity.value == "CRITICAL"),
        high_count=sum(1 for f in findings if f.severity.value == "HIGH"),
        medium_count=sum(1 for f in findings if f.severity.value == "MEDIUM"),
        col_x=col_x,
    )

