from pathlib import Path
from secskill.scripts.index_repo import index_repository
from secskill.scripts.secret_scan import scan_target, redact_secret, shannon_entropy
from secskill.scripts.dep_scan import audit_packages
from secskill.scripts.normalize_findings import normalize_all
from secskill.scripts.to_sarif import convert_findings_to_sarif

def test_index_repo(tmp_path: Path):
    (tmp_path / "app.py").write_text("@app.route('/test')\ndef t(): pass", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("flask==2.0.1", encoding="utf-8")
    index = index_repository(str(tmp_path))
    assert index["total_files"] == 2
    assert "requirements.txt" in index["manifests"]
    assert "app.py" in index["routes"]

def test_secret_scan_and_redaction(tmp_path: Path):
    f = tmp_path / "config.py"
    f.write_text("AWS_KEY = 'AKIAIOSFODNN7REALKEY'", encoding="utf-8")
    findings = scan_target(str(f))
    assert len(findings) == 1
    assert findings[0]["cwe"] == "CWE-798"
    assert "AKIA" in findings[0]["evidence"]
    assert "AKIAIOSFODNN7REALKEY" not in findings[0]["evidence"]
    assert redact_secret("AKIA1234567890ABCDEF") == "AKIA...DEF"

def test_entropy():
    ent = shannon_entropy("AAAAAAAAAA")
    assert ent == 0.0
    ent_high = shannon_entropy("a8F#9$qL2!zP@1vB")
    assert ent_high > 3.5

def test_dep_scan():
    findings = audit_packages([{"name": "pyyaml", "version": "5.1", "ecosystem": "pypi", "file": "reqs.txt"}])
    assert len(findings) >= 1
    assert findings[0]["cwe"] == "CWE-1395"
    assert "CVE-2020-14343" in findings[0]["evidence"]

def test_normalize_and_sarif():
    raw_findings = [[{
        "finding_id": "F-01",
        "title": "SQL Injection",
        "cwe": "CWE-89",
        "severity": "CRITICAL",
        "file": "db.py",
        "line": 15,
        "evidence": "Raw cursor execute"
    }]]
    normalized = normalize_all(raw_findings)
    assert len(normalized) == 1
    assert normalized[0]["owasp"] == "A03:2021-Injection"
    assert normalized[0]["severity"] == "critical"

    sarif = convert_findings_to_sarif(normalized)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 1
    assert sarif["runs"][0]["results"][0]["ruleId"] == "SEC-89"
