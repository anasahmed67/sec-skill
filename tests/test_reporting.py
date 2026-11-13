import json
from typer.testing import CliRunner
from secskill.models import ScanReport, Finding, Severity
from secskill.reporting.sarif_report import SarifReporter

runner = CliRunner()

def test_sarif_generation():
    rep = ScanReport(scan_id="123", target_path=".", timestamp="2026-10-31T00:00:00Z", findings=[
        Finding(id="1", rule_id="R1", title="V", description="D", severity=Severity.HIGH, file_path="main.py", line_number=5)
    ])
    sarif_str = SarifReporter().generate(rep)
    data = json.loads(sarif_str)
    assert data["version"] == "2.1.0"
    assert len(data["runs"][0]["results"]) == 1

