from secskill.models import Finding, Severity, Confidence

def test_finding_creation():
    finding = Finding(
        id="TEST-01",
        rule_id="R-01",
        title="Test Vuln",
        description="A test vulnerability description",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        file_path="app.py",
        line_number=10
    )
    assert finding.id == "TEST-01"
    assert finding.severity == Severity.HIGH
