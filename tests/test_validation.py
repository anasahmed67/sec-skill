from secskill.validation.filter import FindingFilter
from secskill.models import Finding, Severity, ScanContext

def test_filter_ignore():
    f1 = Finding(id="1", rule_id="R1", title="Vuln", description="", severity=Severity.HIGH, file_path="a.py", line_number=1, code_snippet="eval(x)  # secskill:ignore")
    f2 = Finding(id="2", rule_id="R2", title="Vuln", description="", severity=Severity.HIGH, file_path="b.py", line_number=1, code_snippet="eval(x)")
    ctx = ScanContext(target_path=".")
    flt = FindingFilter()
    res = flt.apply([f1, f2], ctx)
    assert len(res) == 1
    assert res[0].id == "2"
