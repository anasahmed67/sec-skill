from secskill.analyzers.static_analysis import StaticAnalyzer
from secskill.analyzers.secret_scan import SecretAnalyzer
from secskill.models import ScanContext
from pathlib import Path

def test_static_analyzer(tmp_path: Path):
    vuln_file = tmp_path / "vuln.py"
    vuln_file.write_text("eval(user_input)", encoding="utf-8")
    ctx = ScanContext(target_path=str(tmp_path), files=["vuln.py"], languages=["python"])
    analyzer = StaticAnalyzer()
    findings = analyzer.analyze(ctx)
    assert len(findings) >= 1
    assert any("eval" in f.title.lower() for f in findings)
