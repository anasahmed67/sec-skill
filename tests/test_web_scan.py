"""Unit and integration tests for WebSecurityScanner and secskill scan-url CLI."""
from pathlib import Path
from typer.testing import CliRunner
import httpx
from secskill.cli import app
from secskill.analyzers.web_scan import WebSecurityScanner

runner = CliRunner()

def test_web_scanner_headers_audit_findings():
    scanner = WebSecurityScanner()
    
    # Construct a mock HTTP response lacking security headers
    mock_resp = httpx.Response(
        status_code=200,
        headers={
            "Content-Type": "text/html",
            "Server": "Apache/2.4.41 (Ubuntu)",
            "X-Powered-By": "PHP/7.4.3",
            "Set-Cookie": "session_id=abc123456; Path=/",
        },
        request=httpx.Request("GET", "https://example.com/app")
    )
    
    findings = scanner._audit_headers(mock_resp, "https://example.com/app")
    rule_ids = [f.rule_id for f in findings]
    
    assert "WEB-HDR-001" in rule_ids  # Missing CSP
    assert "WEB-HDR-003" in rule_ids  # Missing HSTS
    assert "WEB-HDR-005" in rule_ids  # Missing XFO
    assert "WEB-HDR-006" in rule_ids  # Missing XCTO
    assert "WEB-HDR-007" in rule_ids  # Server banner disclosure

def test_web_scanner_cookie_audit_findings():
    scanner = WebSecurityScanner()
    
    mock_resp = httpx.Response(
        status_code=200,
        headers=[
            ("Set-Cookie", "session_id=insecure_token; Path=/"),
        ],
        request=httpx.Request("GET", "https://example.com/login")
    )
    
    cookie_findings = scanner._audit_cookies(mock_resp, "https://example.com/login")
    assert len(cookie_findings) >= 2
    rule_ids = [f.rule_id for f in cookie_findings]
    assert "WEB-COOKIE-001" in rule_ids  # Missing HttpOnly
    assert "WEB-COOKIE-002" in rule_ids  # Missing Secure

def test_web_scanner_compliance_summary():
    scanner = WebSecurityScanner()
    mock_resp = httpx.Response(
        status_code=200,
        headers={"Content-Type": "text/html"},
        request=httpx.Request("GET", "https://example.com")
    )
    findings = scanner._audit_headers(mock_resp, "https://example.com")
    summary = scanner._summarize_compliance(findings)
    
    assert "frameworks" in summary
    assert "owasp_top10" in summary["frameworks"]
    assert "nist_sp_800_53" in summary["frameworks"]
    assert "iso_iec_27001" in summary["frameworks"]

def test_cli_scan_url_console():
    # Run CLI scan against localhost or a dummy non-resolvable host to verify graceful handling
    result = runner.invoke(app, ["scan-url", "https://127.0.0.1:59999", "--no-probes", "--timeout", "1.0"])
    assert result.exit_code == 0
    assert "Target URL:" in result.stdout
    assert "Website Audit Overview" in result.stdout

def test_cli_scan_url_json_output(tmp_path: Path):
    out_file = tmp_path / "web_report.json"
    result = runner.invoke(app, ["scan-url", "https://127.0.0.1:59999", "--format", "json", "--output", str(out_file), "--no-probes", "--timeout", "1.0"])
    assert result.exit_code == 0
    assert out_file.is_file()
    assert "target_url" in out_file.read_text(encoding="utf-8")

