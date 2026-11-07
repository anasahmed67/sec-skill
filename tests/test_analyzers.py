from pathlib import Path
from secskill.analyzers.static_analysis import StaticAnalyzer
from secskill.analyzers.secret_scan import SecretAnalyzer
from secskill.analyzers.dependency_scan import DependencyAnalyzer
from secskill.models import ScanContext

def test_static_analyzer(tmp_path: Path):
    vuln_file = tmp_path / "vuln.py"
    vuln_file.write_text("eval(user_input)", encoding="utf-8")
    ctx = ScanContext(target_path=str(tmp_path), files=["vuln.py"], languages=["python"])
    analyzer = StaticAnalyzer()
    findings = analyzer.analyze(ctx)
    assert len(findings) >= 1
    assert any("eval" in f.title.lower() for f in findings)

def test_owasp_top10_and_cwe_rules(tmp_path: Path):
    app_file = tmp_path / "app.py"
    app_file.write_text(
        "import hashlib\n"
        "h = hashlib.md5(b'password').hexdigest()\n"
        "app.run(debug=True)\n",
        encoding="utf-8"
    )
    ctx = ScanContext(target_path=str(tmp_path), files=["app.py"], languages=["python"])
    analyzer = StaticAnalyzer()
    findings = analyzer.analyze(ctx)
    assert len(findings) >= 2
    # Verify OWASP and CWE mapping
    cwe_ids = [f.cwe_id for f in findings if f.cwe_id]
    owasp_cats = [f.owasp_category for f in findings if f.owasp_category]
    assert any("CWE-327" in c for c in cwe_ids)
    assert any("A02:2021" in o for o in owasp_cats)
    assert any(f.remediation is not None for f in findings)

def test_dependency_analyzer(tmp_path: Path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("pyyaml==5.1\nrequests==2.20.0\n", encoding="utf-8")
    ctx = ScanContext(target_path=str(tmp_path), files=["requirements.txt"])
    analyzer = DependencyAnalyzer()
    findings = analyzer.analyze(ctx)
    assert len(findings) >= 2
    titles = [f.title for f in findings]
    assert any("pyyaml" in t.lower() for t in titles)
    assert any("requests" in t.lower() for t in titles)
    assert all(f.owasp_category == "A06:2021-Vulnerable and Outdated Components" for f in findings)
