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

