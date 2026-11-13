"""
secskill/analyzers/web_scan.py
Dynamic Application Security Testing (DAST) & Live Website Analyzer.
Audits URLs, websites, and APIs against international security standards
(OWASP Top 10, OWASP API Top 10, NIST SP 800-53, ISO/IEC 27001, PCI-DSS v4.0).
"""
import ssl
import socket
import urllib.parse
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
import httpx
from pydantic import BaseModel, Field
from secskill.models import Finding, Severity, Confidence

class WebScanReport(BaseModel):
    target_url: str
    timestamp: str
    status_code: Optional[int] = None
    final_url: Optional[str] = None
    tls_info: Dict[str, Any] = Field(default_factory=dict)
    findings: List[Finding] = Field(default_factory=list)
    headers_analyzed: Dict[str, str] = Field(default_factory=dict)
    compliance_summary: Dict[str, Any] = Field(default_factory=dict)

class WebSecurityScanner:
    """Audits live websites, URLs, and APIs for security misconfigurations and vulnerabilities."""

    SENSITIVE_PATHS = [
        ("/.env", "Exposed Environment Configuration File", Severity.CRITICAL, "CWE-540"),
        ("/.git/HEAD", "Exposed Git Source Code Repository", Severity.CRITICAL, "CWE-540"),
        ("/actuator/health", "Exposed Spring Boot Actuator Endpoint", Severity.MEDIUM, "CWE-200"),
        ("/swagger.json", "Publicly Exposed Swagger API Definition", Severity.LOW, "CWE-200"),
        ("/openapi.json", "Publicly Exposed OpenAPI Specification", Severity.LOW, "CWE-200"),
        ("/robots.txt", "Robots.txt Information Disclosure", Severity.INFO, "CWE-200"),
    ]

    def __init__(self, timeout: float = 8.0, user_agent: Optional[str] = None):
        self.timeout = timeout
        self.user_agent = user_agent or "SecSkill-AgentSec/1.0 (+https://github.com/anasahmed67/sec-skill)"

    def scan_url(self, url: str, check_sensitive_paths: bool = True) -> WebScanReport:
        """Run full DAST security audit on target URL."""
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or url
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        timestamp = datetime.now(timezone.utc).isoformat()

        report = WebScanReport(target_url=url, timestamp=timestamp)
        findings: List[Finding] = []

        # 1. Transport & TLS/SSL Audit
        tls_info = {}
        if parsed.scheme == "https":
            tls_findings, tls_info = self._audit_tls(host, port, url)
            findings.extend(tls_findings)
            report.tls_info = tls_info
        else:
            findings.append(
                Finding(
                    id=f"WEB-INSECURE-HTTP-{host}",
                    rule_id="WEB-TLS-001",
                    title="Unencrypted Cleartext HTTP Protocol in Use",
                    description=f"The endpoint '{url}' uses plaintext HTTP. All communication, credentials, and session tokens are transmitted in cleartext.",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    file_path=url,
                    line_number=1,
                    code_snippet=url,
                    cwe_id="CWE-319",
                    owasp_category="A02:2021-Cryptographic Failures",
                    remediation="Migrate site to HTTPS, redirect all HTTP traffic to HTTPS with 301 Moved Permanently, and enable HSTS.",
                    metadata={
                        "nist_800_53": "SC-8 Transmission Confidentiality and Integrity",
                        "iso_27001": "A.8.24 Use of Cryptography",
                        "pci_dss": "Req 4.1 Encrypt sensitive data in transit",
                    }
                )
            )

        # 2. HTTP Request & Headers Audit
        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=True, verify=False) as client:
                headers = {"User-Agent": self.user_agent}
                resp = client.get(url, headers=headers)
                report.status_code = resp.status_code
                report.final_url = str(resp.url)
                report.headers_analyzed = dict(resp.headers)

                # Check security headers
                header_findings = self._audit_headers(resp, url)
                findings.extend(header_findings)

                # Check cookies
                cookie_findings = self._audit_cookies(resp, url)
                findings.extend(cookie_findings)

                # Check CORS misconfiguration
                cors_findings = self._audit_cors(client, url, headers)
                findings.extend(cors_findings)

                # 3. Check Sensitive Endpoint Exposures
                if check_sensitive_paths:
                    path_findings = self._audit_sensitive_paths(client, parsed.scheme, host, port)
                    findings.extend(path_findings)

        except Exception as e:
            findings.append(
                Finding(
                    id=f"WEB-CONNECT-ERR-{host}",
                    rule_id="WEB-CONN-001",
                    title="Website Connection or Network Audit Warning",
                    description=f"SecSkill could not complete HTTP inspection for '{url}': {str(e)}",
                    severity=Severity.INFO,
                    confidence=Confidence.LOW,
                    file_path=url,
                    line_number=1,
                    code_snippet=str(e),
                    cwe_id="CWE-754",
                    owasp_category="A05:2021-Security Misconfiguration",
                    remediation="Verify that the website or API server is running and accessible over the network.",
                    metadata={"error": str(e)}
                )
            )

        report.findings = findings
        report.compliance_summary = self._summarize_compliance(findings)
        return report

    def _audit_tls(self, host: str, port: int, url: str) -> tuple[List[Finding], Dict[str, Any]]:
        findings = []
        tls_info: Dict[str, Any] = {}

        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    tls_version = ssock.version()
                    cipher = ssock.cipher()

                    tls_info = {
                        "version": tls_version,
                        "cipher": cipher[0] if cipher else "unknown",
                        "bits": cipher[2] if cipher else 0,
                    }

                    # Check deprecated TLS version
                    if tls_version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                        findings.append(
                            Finding(
                                id=f"WEB-TLS-DEPRECATED-{host}",
                                rule_id="WEB-TLS-002",
                                title=f"Deprecated TLS Protocol Version Detected ({tls_version})",
                                description=f"The server negotiates {tls_version}, which is vulnerable to POODLE, BEAST, and SWEET32 attacks.",
                                severity=Severity.HIGH,
                                confidence=Confidence.HIGH,
                                file_path=url,
                                line_number=1,
                                cwe_id="CWE-326",
                                owasp_category="A02:2021-Cryptographic Failures",
                                remediation="Disable TLS 1.0 and TLS 1.1 on your reverse proxy or web server. Enforce TLS 1.2 or TLS 1.3.",
                                metadata={
                                    "nist_800_53": "SC-8 Transmission Confidentiality",
                                    "iso_27001": "A.8.24 Use of Cryptography",
                                    "pci_dss": "Req 4.1 Strong Cryptography",
                                }
                            )
                        )

                    # Check certificate expiry
                    if cert and "notAfter" in cert:
                        not_after = ssl.cert_time_to_seconds(cert["notAfter"])
                        remaining_days = (not_after - datetime.now(timezone.utc).timestamp()) / 86400
                        tls_info["days_until_expiration"] = round(remaining_days, 1)

                        if remaining_days < 0:
                            findings.append(
                                Finding(
                                    id=f"WEB-CERT-EXPIRED-{host}",
                                    rule_id="WEB-TLS-003",
                                    title="Expired SSL/TLS Certificate Detected",
                                    description=f"The TLS certificate for {host} expired {abs(round(remaining_days))} days ago.",
                                    severity=Severity.CRITICAL,
                                    confidence=Confidence.HIGH,
                                    file_path=url,
                                    line_number=1,
                                    cwe_id="CWE-295",
                                    owasp_category="A02:2021-Cryptographic Failures",
                                    remediation="Renew and install a valid TLS certificate immediately via Let's Encrypt or your certificate authority.",
                                    metadata={"nist_800_53": "SC-8", "iso_27001": "A.8.24", "pci_dss": "Req 4.1"}
                                )
                            )
                        elif remaining_days < 14:
                            findings.append(
                                Finding(
                                    id=f"WEB-CERT-EXPIRING-SOON-{host}",
                                    rule_id="WEB-TLS-004",
                                    title="SSL/TLS Certificate Expiring Soon",
                                    description=f"The TLS certificate for {host} will expire in {round(remaining_days, 1)} days.",
                                    severity=Severity.MEDIUM,
                                    confidence=Confidence.HIGH,
                                    file_path=url,
                                    line_number=1,
                                    cwe_id="CWE-295",
                                    owasp_category="A02:2021-Cryptographic Failures",
                                    remediation="Renew the SSL/TLS certificate prior to expiration to avoid browser warnings and service outages.",
                                    metadata={"nist_800_53": "SC-8", "iso_27001": "A.8.24"}
                                )
                            )
        except ssl.SSLCertVerificationError as e:
            findings.append(
                Finding(
                    id=f"WEB-CERT-INVALID-{host}",
                    rule_id="WEB-TLS-005",
                    title="Invalid or Self-Signed SSL/TLS Certificate",
                    description=f"TLS certificate verification failed: {str(e)}",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    file_path=url,
                    line_number=1,
                    cwe_id="CWE-295",
                    owasp_category="A02:2021-Cryptographic Failures",
                    remediation="Install a valid certificate issued by a trusted Certificate Authority (CA).",
                    metadata={"nist_800_53": "SC-8", "iso_27001": "A.8.24"}
                )
            )
        except Exception as e:
            tls_info["error"] = str(e)

        return findings, tls_info

    def _audit_headers(self, resp: httpx.Response, url: str) -> List[Finding]:
        findings = []
        headers = {k.lower(): v for k, v in resp.headers.items()}
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or url

        # 1. Content-Security-Policy
        csp = headers.get("content-security-policy")
        if not csp:
            findings.append(
                Finding(
                    id=f"WEB-CSP-MISSING-{host}",
                    rule_id="WEB-HDR-001",
                    title="Missing Content-Security-Policy (CSP) Header",
                    description="The server does not send a Content-Security-Policy header, leaving client browsers susceptible to Cross-Site Scripting (XSS) and data injection.",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    file_path=url,
                    line_number=1,
                    cwe_id="CWE-1021",
                    owasp_category="A05:2021-Security Misconfiguration",
                    remediation="Define a strong CSP header, e.g.: default-src 'self'; script-src 'self'; object-src 'none';",
                    metadata={"nist_800_53": "SI-10 Information Input Validation", "iso_27001": "A.8.26", "pci_dss": "Req 6.4.1"}
                )
            )
        elif "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
            findings.append(
                Finding(
                    id=f"WEB-CSP-UNSAFE-{host}",
                    rule_id="WEB-HDR-002",
                    title="Permissive Content-Security-Policy with 'unsafe-inline' or 'unsafe-eval'",
                    description="The Content-Security-Policy permits 'unsafe-inline' or 'unsafe-eval', drastically weakening XSS protections.",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    file_path=url,
                    line_number=1,
                    code_snippet=csp[:120],
                    cwe_id="CWE-1021",
                    owasp_category="A05:2021-Security Misconfiguration",
                    remediation="Refactor inline scripts and use cryptographic nonces or SHA hashes for allowed inline resources.",
                    metadata={"nist_800_53": "SI-10", "iso_27001": "A.8.26"}
                )
            )

        # 2. Strict-Transport-Security (HSTS)
        hsts = headers.get("strict-transport-security")
        if parsed.scheme == "https":
            if not hsts:
                findings.append(
                    Finding(
                        id=f"WEB-HSTS-MISSING-{host}",
                        rule_id="WEB-HDR-003",
                        title="Missing HTTP Strict-Transport-Security (HSTS) Header",
                        description="HSTS is not configured on this HTTPS website. Attackers on adjacent networks can downgrade traffic via SSL stripping.",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        file_path=url,
                        line_number=1,
                        cwe_id="CWE-319",
                        owasp_category="A05:2021-Security Misconfiguration",
                        remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to all HTTPS responses.",
                        metadata={"nist_800_53": "SC-8", "iso_27001": "A.8.20", "pci_dss": "Req 4.1"}
                    )
                )
            elif "max-age" in hsts:
                try:
                    max_age_val = int(hsts.split("max-age=")[1].split(";")[0].strip())
                    if max_age_val < 15768000:  # Less than 6 months
                        findings.append(
                            Finding(
                                id=f"WEB-HSTS-SHORT-{host}",
                                rule_id="WEB-HDR-004",
                                title="HSTS max-age Duration Too Short",
                                description=f"HSTS max-age is set to {max_age_val} seconds, below recommended minimum (31536000 seconds / 1 year).",
                                severity=Severity.LOW,
                                confidence=Confidence.HIGH,
                                file_path=url,
                                line_number=1,
                                code_snippet=hsts,
                                cwe_id="CWE-319",
                                owasp_category="A05:2021-Security Misconfiguration",
                                remediation="Increase Strict-Transport-Security max-age to at least 31536000 seconds (1 year).",
                                metadata={"nist_800_53": "SC-8", "iso_27001": "A.8.20"}
                            )
                        )
                except Exception:
                    pass

        # 3. X-Frame-Options / Clickjacking
        xfo = headers.get("x-frame-options")
        if not xfo and (not csp or "frame-ancestors" not in csp):
            findings.append(
                Finding(
                    id=f"WEB-XFO-MISSING-{host}",
                    rule_id="WEB-HDR-005",
                    title="Missing Clickjacking Defense (X-Frame-Options or CSP frame-ancestors)",
                    description="The web page does not specify X-Frame-Options or frame-ancestors, allowing malicious sites to iframe the page for UI redress attacks.",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    file_path=url,
                    line_number=1,
                    cwe_id="CWE-1021",
                    owasp_category="A05:2021-Security Misconfiguration",
                    remediation="Set 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN', or use CSP 'frame-ancestors 'self''.",
                    metadata={"nist_800_53": "SI-10", "iso_27001": "A.8.26", "pci_dss": "Req 6.4.1"}
                )
            )

        # 4. X-Content-Type-Options
        xcto = headers.get("x-content-type-options")
        if not xcto or xcto.lower() != "nosniff":
            findings.append(
                Finding(
                    id=f"WEB-XCTO-MISSING-{host}",
                    rule_id="WEB-HDR-006",
                    title="Missing X-Content-Type-Options: nosniff Header",
                    description="Without X-Content-Type-Options: nosniff, older browsers may MIME-sniff response content, leading to executable script injection.",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    file_path=url,
                    line_number=1,
                    cwe_id="CWE-79",
                    owasp_category="A05:2021-Security Misconfiguration",
                    remediation="Add 'X-Content-Type-Options: nosniff' header to all server responses.",
                    metadata={"nist_800_53": "SI-10", "iso_27001": "A.8.26"}
                )
            )

        # 5. Technology Disclosure (Server, X-Powered-By)
        server_hdr = headers.get("server")
        powered_by = headers.get("x-powered-by")
        if powered_by or (server_hdr and any(c.isdigit() for c in server_hdr)):
            disclosure = f"Server: {server_hdr}" if server_hdr else ""
            if powered_by:
                disclosure += f" | X-Powered-By: {powered_by}"
            findings.append(
                Finding(
                    id=f"WEB-BANNER-DISCLOSURE-{host}",
                    rule_id="WEB-HDR-007",
                    title="Server Version & Technology Stack Fingerprint Disclosed",
                    description=f"Detailed server banner disclosed: '{disclosure}'. Attackers use this to identify target CVEs.",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    file_path=url,
                    line_number=1,
                    code_snippet=disclosure,
                    cwe_id="CWE-200",
                    owasp_category="A05:2021-Security Misconfiguration",
                    remediation="Configure web server to suppress or genericize Server tokens (e.g. ServerTokens Prod in Apache) and remove X-Powered-By.",
                    metadata={"nist_800_53": "SC-28", "iso_27001": "A.8.20"}
                )
            )

        return findings

    def _audit_cookies(self, resp: httpx.Response, url: str) -> List[Finding]:
        findings = []
        host = urllib.parse.urlparse(url).hostname or url
        set_cookie_headers = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else [resp.headers.get("set-cookie", "")]

        for raw_cookie in set_cookie_headers:
            if not raw_cookie:
                continue
            cookie_parts = [p.strip() for p in raw_cookie.split(";")]
            cookie_name = cookie_parts[0].split("=")[0] if "=" in cookie_parts[0] else "cookie"
            cookie_attrs = [p.strip().lower() for p in cookie_parts[1:]]
            has_httponly = any(a == "httponly" for a in cookie_attrs)
            has_secure = any(a == "secure" for a in cookie_attrs)
            has_samesite = any(a.startswith("samesite") for a in cookie_attrs)

            # Check HttpOnly
            if not has_httponly:
                findings.append(
                    Finding(
                        id=f"WEB-COOKIE-NO-HTTPONLY-{host}-{cookie_name}",
                        rule_id="WEB-COOKIE-001",
                        title=f"Cookie '{cookie_name}' Missing HttpOnly Flag",
                        description=f"The cookie '{cookie_name}' lacks the HttpOnly attribute, allowing JavaScript access via document.cookie during an XSS attack.",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        file_path=url,
                        line_number=1,
                        code_snippet=raw_cookie[:80],
                        cwe_id="CWE-1004",
                        owasp_category="A05:2021-Security Misconfiguration",
                        remediation=f"Set 'HttpOnly' flag on cookie '{cookie_name}' to prevent client-side script access.",
                        metadata={"nist_800_53": "SC-28", "iso_27001": "A.8.26", "pci_dss": "Req 6.4"}
                    )
                )

            # Check Secure flag
            if not has_secure:
                findings.append(
                    Finding(
                        id=f"WEB-COOKIE-NO-SECURE-{host}-{cookie_name}",
                        rule_id="WEB-COOKIE-002",
                        title=f"Cookie '{cookie_name}' Missing Secure Flag",
                        description=f"The cookie '{cookie_name}' can be transmitted over unencrypted HTTP connections in cleartext.",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        file_path=url,
                        line_number=1,
                        code_snippet=raw_cookie[:80],
                        cwe_id="CWE-614",
                        owasp_category="A05:2021-Security Misconfiguration",
                        remediation=f"Set 'Secure' attribute on cookie '{cookie_name}' so it is only transmitted via HTTPS.",
                        metadata={"nist_800_53": "SC-8", "iso_27001": "A.8.24", "pci_dss": "Req 4.1"}
                    )
                )

            # Check SameSite
            if not has_samesite:
                findings.append(
                    Finding(
                        id=f"WEB-COOKIE-NO-SAMESITE-{host}-{cookie_name}",
                        rule_id="WEB-COOKIE-003",
                        title=f"Cookie '{cookie_name}' Missing SameSite Attribute",
                        description=f"The cookie '{cookie_name}' does not specify SameSite=Lax or SameSite=Strict, increasing exposure to Cross-Site Request Forgery (CSRF).",
                        severity=Severity.LOW,
                        confidence=Confidence.HIGH,
                        file_path=url,
                        line_number=1,
                        code_snippet=raw_cookie[:80],
                        cwe_id="CWE-1275",
                        owasp_category="A01:2021-Broken Access Control",
                        remediation=f"Add 'SameSite=Lax' or 'SameSite=Strict' to cookie '{cookie_name}'.",
                        metadata={"nist_800_53": "AC-3", "iso_27001": "A.8.26"}
                    )
                )

        return findings

    def _audit_cors(self, client: httpx.Client, url: str, base_headers: Dict[str, str]) -> List[Finding]:
        findings = []
        host = urllib.parse.urlparse(url).hostname or url
        test_origin = "https://evil-attacker.example.com"
        probe_headers = dict(base_headers)
        probe_headers["Origin"] = test_origin

        try:
            cors_resp = client.get(url, headers=probe_headers, timeout=self.timeout)
            allow_origin = cors_resp.headers.get("access-control-allow-origin", "")
            allow_credentials = cors_resp.headers.get("access-control-allow-credentials", "").lower()

            if allow_origin == "*" and allow_credentials == "true":
                findings.append(
                    Finding(
                        id=f"WEB-CORS-WILDCARD-CREDS-{host}",
                        rule_id="WEB-CORS-001",
                        title="Critical CORS Misconfiguration: Wildcard Origin with Credentials",
                        description="Access-Control-Allow-Origin is set to '*' while Access-Control-Allow-Credentials is true, enabling unauthorized cross-origin credential theft.",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH,
                        file_path=url,
                        line_number=1,
                        code_snippet=f"Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true",
                        cwe_id="CWE-942",
                        owasp_category="A01:2021-Broken Access Control",
                        remediation="Explicitly whitelist allowed origins and never allow credentials alongside wildcard origins.",
                        metadata={"nist_800_53": "AC-3", "iso_27001": "A.8.26", "pci_dss": "Req 6.4.1"}
                    )
                )
            elif allow_origin == test_origin and allow_credentials == "true":
                findings.append(
                    Finding(
                        id=f"WEB-CORS-REFLECTED-ORIGIN-{host}",
                        rule_id="WEB-CORS-002",
                        title="Insecure CORS Origin Reflection with Credentials",
                        description=f"Server dynamically reflects untrusted Origin header ('{test_origin}') with Access-Control-Allow-Credentials=true.",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        file_path=url,
                        line_number=1,
                        code_snippet=f"Origin: {test_origin}\nAccess-Control-Allow-Origin: {allow_origin}",
                        cwe_id="CWE-942",
                        owasp_category="A01:2021-Broken Access Control",
                        remediation="Validate Origin against a server-side whitelist of trusted domains rather than reflecting arbitrary incoming origins.",
                        metadata={"nist_800_53": "AC-3", "iso_27001": "A.8.26"}
                    )
                )
        except Exception:
            pass

        return findings

    def _audit_sensitive_paths(self, client: httpx.Client, scheme: str, host: str, port: int) -> List[Finding]:
        findings = []
        base_url = f"{scheme}://{host}"
        if (scheme == "https" and port != 443) or (scheme == "http" and port != 80):
            base_url += f":{port}"

        for path, title, sev, cwe in self.SENSITIVE_PATHS:
            target_probe = f"{base_url}{path}"
            try:
                probe_resp = client.get(target_probe, headers={"User-Agent": self.user_agent}, timeout=3.0)
                # Flag 200 OK with non-trivial content length
                if probe_resp.status_code == 200 and len(probe_resp.text.strip()) > 5:
                    # Filter out generic 404 soft pages disguised as 200
                    text_lower = probe_resp.text.lower()
                    if "page not found" in text_lower or "<!doctype html" in text_lower and path.endswith((".env", "/HEAD")):
                        continue

                    findings.append(
                        Finding(
                            id=f"WEB-EXPOSED-FILE-{host}-{path.replace('/', '_').strip('_')}",
                            rule_id="WEB-EXP-001",
                            title=f"Publicly Accessible Sensitive Endpoint: {path}",
                            description=f"The endpoint '{target_probe}' returned HTTP 200 OK. {title}.",
                            severity=sev,
                            confidence=Confidence.HIGH,
                            file_path=target_probe,
                            line_number=1,
                            code_snippet=probe_resp.text[:120].strip(),
                            cwe_id=cwe,
                            owasp_category="A05:2021-Security Misconfiguration",
                            remediation=f"Block public access to '{path}' in reverse proxy or web server configuration.",
                            metadata={"nist_800_53": "SC-28", "iso_27001": "A.8.20", "pci_dss": "Req 6.4.1"}
                        )
                    )
            except Exception:
                continue

        return findings

    def _summarize_compliance(self, findings: List[Finding]) -> Dict[str, Any]:
        """Aggregate findings against international security frameworks."""
        owasp_counts: Dict[str, int] = {}
        cwe_counts: Dict[str, int] = {}
        nist_counts: Dict[str, int] = {}
        iso_counts: Dict[str, int] = {}

        for f in findings:
            if f.owasp_category:
                cat = f.owasp_category.split("-")[0].strip()
                owasp_counts[cat] = owasp_counts.get(cat, 0) + 1
            if f.cwe_id:
                cwe_counts[f.cwe_id] = cwe_counts.get(f.cwe_id, 0) + 1
            if "nist_800_53" in f.metadata:
                nist_ctrl = f.metadata["nist_800_53"].split()[0]
                nist_counts[nist_ctrl] = nist_counts.get(nist_ctrl, 0) + 1
            if "iso_27001" in f.metadata:
                iso_ctrl = f.metadata["iso_27001"].split()[0]
                iso_counts[iso_ctrl] = iso_counts.get(iso_ctrl, 0) + 1

        return {
            "total_findings": len(findings),
            "critical_count": sum(1 for f in findings if f.severity == Severity.CRITICAL),
            "high_count": sum(1 for f in findings if f.severity == Severity.HIGH),
            "medium_count": sum(1 for f in findings if f.severity == Severity.MEDIUM),
            "low_count": sum(1 for f in findings if f.severity == Severity.LOW),
            "frameworks": {
                "owasp_top10": owasp_counts,
                "cwe": cwe_counts,
                "nist_sp_800_53": nist_counts,
                "iso_iec_27001": iso_counts,
            }
        }
