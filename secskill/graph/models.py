"""Domain models and data structures for Attack Path Visual Graph representation."""
from dataclasses import dataclass
from typing import Dict, List, Any, Optional

@dataclass
class GraphNode:
    """A visual graph node with calculated canvas coordinates."""
    id: str
    label: str
    sub: str
    col: str
    x: float = 0.0
    y: float = 0.0
    severity: Optional[str] = None
    finding_idx: Optional[int] = None

@dataclass
class GraphEdge:
    """A directional connection between nodes in the attack path."""
    idx: int
    src_id: str
    file_id: str
    sink_id: str
    target_id: str
    severity: str

@dataclass
class GraphLayout:
    """Precomputed 2D layout topology ready for rendering."""
    entry_nodes: Dict[str, GraphNode]
    file_nodes: Dict[str, GraphNode]
    sink_nodes: List[GraphNode]
    target_nodes: Dict[str, GraphNode]
    attack_paths: List[GraphEdge]
    findings_data: List[Dict[str, Any]]
    representative_findings_count: int
    canvas_width: int
    canvas_height: int
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    col_x: Dict[str, int]

