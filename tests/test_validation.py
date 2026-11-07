from secskill.validation.filter import FindingFilter
from secskill.validation.reachability import ReachabilityValidator
from secskill.models import Finding, Severity, ScanContext, Confidence

def test_filter_ignore():
    f1 = Finding(id="1", rule_id="R1", title="Vuln", description="", severity=Severity.HIGH, file_path="a.py", line_number=1, code_snippet="eval(x)  # secskill:ignore")
    f2 = Finding(id="2", rule_id="R2", title="Vuln", description="", severity=Severity.HIGH, file_path="b.py", line_number=1, code_snippet="eval(x)")
    ctx = ScanContext(target_path=".")
    flt = FindingFilter()
    res = flt.apply([f1, f2], ctx)
    assert len(res) == 1
    assert res[0].id == "2"

def test_reachability_validator(tmp_path):
    app_file = tmp_path / "routes.py"
    app_file.write_text("@app.route('/transfer')\ndef transfer(): pass\n", encoding="utf-8")
    
    f1 = Finding(id="1", rule_id="R1", title="Route Vuln", description="", severity=Severity.HIGH, file_path="routes.py", line_number=1)
    f2 = Finding(id="2", rule_id="R2", title="Mock Vuln", description="", severity=Severity.HIGH, file_path="tests/test_mock.py", line_number=1)
    
    ctx = ScanContext(target_path=str(tmp_path))
    validator = ReachabilityValidator()
    results = validator.validate([f1, f2], ctx)
    
    # f1 should be reachable entrypoint
    assert results[0].metadata.get("reachable") is True
    assert results[0].metadata.get("entrypoint_reachable") is True
    
    # f2 should be in_test_file and marked reachable=False
    assert results[1].metadata.get("in_test_file") is True
    assert results[1].metadata.get("reachable") is False
    assert results[1].confidence == Confidence.MEDIUM
