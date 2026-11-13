"""Tests for AttackPathGraph and secskill graph CLI command."""
from pathlib import Path
from typer.testing import CliRunner
from secskill.cli import app
from secskill.models import Finding, Severity
from secskill.visual_graph import AttackPathGraph

runner = CliRunner()

def test_infer_attack_path():
    finding_sqli = Finding(
        id="F1",
        rule_id="R-SQL",
        title="SQL Injection in users.py",
        description="f-string SQL",
        severity=Severity.CRITICAL,
        file_path="app/users.py",
        line_number=42,
        code_snippet="cursor.execute(f'SELECT {user_id}')",
        cwe_id="CWE-89",
    )
    path_data = AttackPathGraph.infer_attack_path(finding_sqli)
    assert "HTTP Request" in path_data["source"]
    assert "cursor.execute" in path_data["sink"]
    assert "Database" in path_data["impact"]
    assert "eli5" in path_data
    assert "quick_fix" in path_data
    assert "target_asset" in path_data

def test_interactive_drawer_elements():
    finding = Finding(
        id="F-TEST",
        rule_id="R-CMD",
        title="Command Injection Flaw",
        description="os.system call with unescaped input",
        severity=Severity.CRITICAL,
        file_path="server.py",
        line_number=20,
        code_snippet="os.system('cat ' + file)",
        cwe_id="CWE-78"
    )
    html_out = AttackPathGraph.generate_html([finding], ".")
    assert "inspectorDrawer" in html_out
    assert "Explain Like I&#039;m 5" in html_out or "ELI5" in html_out
    assert "1-Click Safe Remediation" in html_out
    assert "FINDINGS" in html_out

def test_to_mermaid():
    finding = Finding(
        id="F2",
        rule_id="R-CMD",
        title="Command Injection",
        description="os.system call",
        severity=Severity.HIGH,
        file_path="util.py",
        line_number=10,
        cwe_id="CWE-78",
    )
    mmd = AttackPathGraph.to_mermaid(finding)
    assert "```mermaid" in mmd
    assert "flowchart LR" in mmd
    assert "Command Execution" in mmd

def test_generate_html():
    findings = [
        Finding(
            id="F3",
            rule_id="R-XSS",
            title="Cross-Site Scripting",
            description="innerHTML",
            severity=Severity.MEDIUM,
            file_path="index.js",
            line_number=5,
            cwe_id="CWE-79",
        )
    ]
    html_out = AttackPathGraph.generate_html(findings, "test-repo")
    assert "<!DOCTYPE html>" in html_out
    assert "SecSkill Attack Path Visualizer" in html_out
    assert "node-source" in html_out
    assert "node-sink" in html_out

def test_cli_graph_terminal():
    result = runner.invoke(app, ["graph", "."])
    assert result.exit_code == 0
    assert "Visual Dataflow Graph" in result.stdout or "Attack Path" in result.stdout

def test_cli_graph_mermaid():
    result = runner.invoke(app, ["graph", ".", "--format", "mermaid"])
    assert result.exit_code == 0
    assert "flowchart LR" in result.stdout

def test_cli_graph_html(tmp_path: Path):
    out_file = tmp_path / "attack_path.html"
    result = runner.invoke(app, ["graph", ".", "--format", "html", "--output", str(out_file)])
    assert result.exit_code == 0
    assert out_file.is_file()
    assert "Attack Path Visualizer" in out_file.read_text(encoding="utf-8")


def test_calculate_graph_layout_geometry():
    """Unit test for layout geometry and coordinate calculations isolated from HTML/rendering."""
    import io
    from rich.console import Console
    from secskill.graph.layout import calculate_graph_layout
    from secskill.graph.svg import generate_svg_markup
    from secskill.graph.presenters import render_terminal_pipeline

    f1 = Finding(
        id="F-LAYOUT-1",
        rule_id="R-SQL",
        title="SQL Injection",
        description="SQL flaw",
        severity=Severity.CRITICAL,
        file_path="app/db.py",
        line_number=10,
        cwe_id="CWE-89",
    )
    f2 = Finding(
        id="F-LAYOUT-2",
        rule_id="R-CMD",
        title="Command Injection",
        description="RCE flaw",
        severity=Severity.HIGH,
        file_path="app/cmd.py",
        line_number=25,
        cwe_id="CWE-78",
    )

    layout = calculate_graph_layout([f1, f2])
    assert layout.total_findings == 2
    assert layout.critical_count == 1
    assert layout.high_count == 1
    assert len(layout.attack_paths) == 2
    assert layout.canvas_width == 1150
    assert layout.canvas_height >= 700

    # Verify column distribution
    for node in layout.entry_nodes.values():
        assert node.x == 110
        assert node.y > 0
    for node in layout.file_nodes.values():
        assert node.x == 390
        assert node.y > 0
    for node in layout.sink_nodes:
        assert node.x == 680
        assert node.y > 0
    for node in layout.target_nodes.values():
        assert node.x == 980
        assert node.y > 0

    # Test SVG generation in isolation
    edges_svg, nodes_svg = generate_svg_markup(layout)
    assert '<path d="M 110' in edges_svg
    assert "edge-exploit-glow" in edges_svg
    assert "node-entry" in nodes_svg
    assert "node-sink" in nodes_svg

    # Test terminal pipeline with injected in-memory console
    string_io = io.StringIO()
    test_console = Console(file=string_io, force_terminal=False, color_system=None)
    render_terminal_pipeline(f1, console=test_console)
    output = string_io.getvalue()
    assert "Attack Path Dataflow" in output
    assert "Entrypoint (Source)" in output
    assert "cursor.execute" in output


