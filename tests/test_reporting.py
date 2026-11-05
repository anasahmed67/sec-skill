import json
from pathlib import Path
from typer.testing import CliRunner
from secskill.models import ScanReport, Finding, Severity
from secskill.reporting.sarif_report import SarifReporter
from secskill.reporting.html_report import HtmlReporter, calculate_security_score
from secskill.cli import app

runner = CliRunner()

def test_sarif_generation():
    rep = ScanReport(scan_id="123", target_path=".", timestamp="2026-10-31T00:00:00Z", findings=[
        Finding(id="1", rule_id="R1", title="V", description="D", severity=Severity.HIGH, file_path="main.py", line_number=5)
    ])
    sarif_str = SarifReporter().generate(rep)
    data = json.loads(sarif_str)
    assert data["version"] == "2.1.0"
    assert len(data["runs"][0]["results"]) == 1

def test_html_dashboard_generation(tmp_path: Path):
    rep = ScanReport(
        scan_id="scan-xyz",
        target_path=".",
        timestamp="2026-11-05T12:00:00Z",
        findings=[
            Finding(
                id="F1",
                rule_id="SEC-SQL-001",
                title="SQL Injection",
                description="SQL injection in cursor.execute",
                severity=Severity.CRITICAL,
                file_path="app.py",
                line_number=10,
                code_snippet="cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
                remediation="Use parameterized query",
            )
        ]
    )
    score_info = calculate_security_score(rep)
    assert score_info["score"] == 75  # 100 - 25 for critical
    assert score_info["grade"] == "B"

    out_file = tmp_path / "dashboard.html"
    content = HtmlReporter().generate(rep, out_file)
    assert out_file.is_file()
    assert "SecSkill Visual Security Hub" in content
    assert "SQL Injection" in content
    assert "75/100" in content
    assert "cursor.execute" in content

def test_cli_view_command(tmp_path: Path):
    out_file = tmp_path / "custom_dash.html"
    result = runner.invoke(app, ["view", ".", "--output", str(out_file), "--no-open"])
    assert result.exit_code == 0
    assert "Visual Dashboard generated" in result.stdout
    assert out_file.is_file()

