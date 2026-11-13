"""Attack Path and Dataflow Visual Graph Generator (Clean Architecture Facade)."""
from typing import List, Dict, Any, Optional
from rich.console import Console

from secskill.models import Finding
from secskill.graph.inference import infer_attack_path as _infer_attack_path
from secskill.graph.layout import calculate_graph_layout
from secskill.graph.svg import generate_svg_markup
from secskill.graph.presenters import (
    render_terminal_pipeline as _render_terminal_pipeline,
    to_mermaid_flowchart as _to_mermaid_flowchart,
)
from secskill.graph.template import build_interactive_html

console = Console()

class AttackPathGraph:
    """Transforms security findings into visual source-to-sink dataflow graphs.
    
    Serves as a backward-compatible facade delegating to modularized `secskill.graph` components.
    """

    @staticmethod
    def infer_attack_path(finding: Finding) -> Dict[str, Any]:
        """Infer structured source-to-sink steps from a finding."""
        return _infer_attack_path(finding)

    @classmethod
    def to_mermaid(cls, finding: Finding) -> str:
        """Convert a finding into a GitHub-ready Mermaid flowchart."""
        return _to_mermaid_flowchart(finding)

    @classmethod
    def render_terminal(cls, finding: Finding, custom_console: Optional[Console] = None) -> None:
        """Render a clean Unicode pipeline in the console."""
        _render_terminal_pipeline(finding, console=custom_console or console)

    @classmethod
    def generate_html(cls, findings: List[Finding], target_path: str = ".") -> str:
        """Generate a feather-light, lightning-fast interactive SVG attack map."""
        layout = calculate_graph_layout(findings)
        edges_svg, nodes_svg = generate_svg_markup(layout)
        return build_interactive_html(
            layout=layout,
            edges_svg_markup=edges_svg,
            nodes_svg_markup=nodes_svg,
            target_path=target_path,
        )
