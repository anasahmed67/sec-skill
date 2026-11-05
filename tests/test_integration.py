from secskill.context import build_scan_context
from secskill.scanner import SecurityScanner

def test_full_pipeline(tmp_path):
    f = tmp_path / "test.py"
    f.write_text("import subprocess\nsubprocess.run(cmd, shell=True)\n", encoding="utf-8")
    ctx = build_scan_context(str(tmp_path))
    scanner = SecurityScanner()
    report = scanner.scan(ctx)
    assert len(report.findings) > 0
