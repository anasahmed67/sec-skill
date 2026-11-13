"""
secskill/mcp_server.py
Model Context Protocol (MCP) Server for SecSkill.
Enables any MCP-compliant AI agent (Claude Code, Cursor, Windsurf, Codex, Antigravity)
to execute security scans, live website audits, and verified remediations via standard JSON-RPC 2.0.
"""
import sys
import json
import logging
from typing import Dict, Any, Optional

from secskill.context import build_scan_context
from secskill.scanner import SecurityScanner
from secskill.analyzers.web_scan import WebSecurityScanner
from secskill.agent_audit import AgentSecurityAuditor

logger = logging.getLogger("secskill.mcp")

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {
    "name": "secskill",
    "version": "0.2.0"
}

TOOLS = [
    {
        "name": "secskill_scan",
        "description": "Scan a local codebase, directory, git diff, or single file for security vulnerabilities (SQLi, Command Injection, XSS, Path Traversal, Secrets, Vulnerable Dependencies). Maps to OWASP Top 10, CWE Top 25, and NIST SSDF.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to target repository, directory, or file (defaults to current directory).",
                    "default": "."
                },
                "diff": {
                    "type": "string",
                    "description": "Optional git branch or commit to diff against (e.g. 'main')."
                },
                "file": {
                    "type": "string",
                    "description": "Optional single file path to audit."
                },
                "ignore": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional list of paths or glob patterns to ignore."
                },
                "include_secskill": {
                    "type": "boolean",
                    "description": "Set to true to scan internal secskill files and folders. Defaults to false.",
                    "default": False
                }
            }
        }
    },
    {
        "name": "secskill_scan_url",
        "description": "Audit a live website, URL, or API endpoint for transport security (TLS/SSL), HTTP security headers (CSP, HSTS, XFO), CORS misconfigurations, cookie security flags, and exposed sensitive endpoints.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Target website URL (e.g. 'https://example.com' or 'http://localhost:8000')."
                },
                "check_sensitive_paths": {
                    "type": "boolean",
                    "description": "Probe for exposed files like /.env, /.git/HEAD, /actuator, /swagger.",
                    "default": True
                }
            },
            "required": ["url"]
        }
    },
    {
        "name": "secskill_verify_patch",
        "description": "Verify whether a proposed code fix/patch resolves the security vulnerability without introducing regressions. Evaluates baseline vs patched code.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Target source file being patched."
                },
                "proposed_patch": {
                    "type": "string",
                    "description": "Proposed replacement code snippet, complete modified file, or unified diff."
                },
                "original_code": {
                    "type": "string",
                    "description": "Optional original code content if file does not exist on disk."
                }
            },
            "required": ["file_path", "proposed_patch"]
        }
    },
    {
        "name": "secskill_audit_agent",
        "description": "Audit AI Agent architectures, MCP server configurations, tool definitions, and system prompts for OWASP LLM Top 10 vulnerabilities (Prompt Injection, Excessive Agency, Exfiltration, Credential Leakage).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to codebase or agent configuration directory.",
                    "default": "."
                },
                "ignore": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional list of paths or glob patterns to ignore."
                },
                "include_secskill": {
                    "type": "boolean",
                    "description": "Set to true to scan internal secskill files and folders. Defaults to false.",
                    "default": False
                }
            }
        }
    },
    {
        "name": "secskill_explain",
        "description": "Deeply explain a vulnerability, CWE ID, or OWASP category with attack simulations, technical impact, and international compliance remediation advice.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Finding ID, CWE ID (e.g. 'CWE-89'), or OWASP category (e.g. 'A03:2021')."
                }
            },
            "required": ["query"]
        }
    }
]

class SecSkillMCPServer:
    """Stdio-based JSON-RPC 2.0 Model Context Protocol Server."""

    def __init__(self):
        self.scanner = SecurityScanner()
        self.web_scanner = WebSecurityScanner()
        self.agent_auditor = AgentSecurityAuditor()

    def handle_request(self, request: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        msg_id = request.get("id")
        method = request.get("method")
        params = request.get("params", {})

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {
                        "tools": {"listChanged": False}
                    },
                    "serverInfo": SERVER_INFO
                }
            }

        elif method == "notifications/initialized":
            return None

        elif method == "ping":
            return {"jsonrpc": "2.0", "id": msg_id, "result": {}}

        elif method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"tools": TOOLS}
            }

        elif method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments", {})
            try:
                res_content = self._execute_tool(tool_name, arguments)
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "content": [
                            {"type": "text", "text": json.dumps(res_content, indent=2)}
                        ]
                    }
                }
            except Exception as e:
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32603,
                        "message": f"Error executing tool '{tool_name}': {str(e)}"
                    }
                }

        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": f"Method '{method}' not found"}
        }

    def _execute_tool(self, name: str, args: Dict[str, Any]) -> Any:
        if name == "secskill_scan":
            target = args.get("file") or args.get("path", ".")
            extra_ignores = args.get("ignore")
            if isinstance(extra_ignores, str):
                extra_ignores = [p.strip() for p in extra_ignores.split(",") if p.strip()]
            include_secskill = bool(args.get("include_secskill", False))
            ctx = build_scan_context(target, extra_ignores=extra_ignores, include_secskill=include_secskill)
            if args.get("diff"):
                ctx.git_branch = args["diff"]
            report = self.scanner.scan(ctx)
            return {
                "scan_id": report.scan_id,
                "target": report.target_path,
                "summary": report.summary,
                "total_findings": len(report.findings),
                "findings": [f.model_dump() for f in report.findings[:50]],
            }

        elif name == "secskill_scan_url":
            url = args.get("url", "")
            check_paths = bool(args.get("check_sensitive_paths", True))
            report = self.web_scanner.scan_url(url, check_sensitive_paths=check_paths)
            return {
                "target_url": report.target_url,
                "status_code": report.status_code,
                "tls_info": report.tls_info,
                "total_findings": len(report.findings),
                "compliance_summary": report.compliance_summary,
                "findings": [f.model_dump() for f in report.findings],
            }

        elif name == "secskill_verify_patch":
            from secskill.agent_skill import SecSkillAgentSkill
            agent_skill = SecSkillAgentSkill()
            return agent_skill.verify_remediation(
                file_path=args.get("file_path", ""),
                proposed_patch=args.get("proposed_patch", ""),
                original_code=args.get("original_code")
            )

        elif name == "secskill_audit_agent":
            target = args.get("path", ".")
            extra_ignores = args.get("ignore")
            if isinstance(extra_ignores, str):
                extra_ignores = [p.strip() for p in extra_ignores.split(",") if p.strip()]
            include_secskill = bool(args.get("include_secskill", False))
            report = self.agent_auditor.audit(target, extra_ignores=extra_ignores, include_secskill=include_secskill)
            return {
                "target": report.target_path,
                "trust_index": report.security_score,
                "grade": report.grade,
                "findings_count": len(report.findings),
                "findings": [f.model_dump() for f in report.findings],
            }

        elif name == "secskill_explain":
            q = args.get("query", "").lower()
            return self._explain_query(q)

        raise ValueError(f"Unknown tool '{name}'")

    def _explain_query(self, q: str) -> Dict[str, Any]:
        if "89" in q or "sql" in q:
            return {
                "cwe": "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
                "owasp": "A03:2021-Injection",
                "severity": "CRITICAL",
                "attack_vector": "Attacker injects characters like ' OR 1=1 -- to alter SQL AST and bypass auth or exfiltrate data.",
                "remediation": "Always use driver-level parameterized queries or ORM bindings. Never interpolate user variables directly into query strings.",
                "standards": {"nist": "SI-10", "iso_27001": "A.8.28", "pci_dss": "Req 6.2.4"}
            }
        elif "78" in q or "cmd" in q:
            return {
                "cwe": "CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
                "owasp": "A03:2021-Injection",
                "severity": "CRITICAL",
                "attack_vector": "Attacker supplies shell metacharacters (; | & ` $()) to execute arbitrary operating system commands.",
                "remediation": "Use subprocess APIs with discrete argument lists and shell=False (e.g. subprocess.run(['ls', path], shell=False)).",
                "standards": {"nist": "SI-10", "iso_27001": "A.8.28", "pci_dss": "Req 6.2.4"}
            }
        elif "79" in q or "xss" in q:
            return {
                "cwe": "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
                "owasp": "A03:2021-Injection",
                "severity": "HIGH",
                "attack_vector": "Attacker injects malicious JavaScript executed in the victim's browser session.",
                "remediation": "Contextually encode user output (HTML, attribute, JS), use DOMPurify, and enforce a strict Content-Security-Policy.",
                "standards": {"nist": "SI-10", "iso_27001": "A.8.26", "pci_dss": "Req 6.4.1"}
            }
        elif "798" in q or "secret" in q:
            return {
                "cwe": "CWE-798: Use of Hard-coded Credentials",
                "owasp": "A02:2021-Cryptographic Failures",
                "severity": "CRITICAL",
                "attack_vector": "Adversaries extract plain secrets from git commits or client-side assets to compromise cloud infrastructure.",
                "remediation": "Revoke and rotate credentials immediately. Store secrets in environment variables or key vaults (AWS Secrets Manager, Vault).",
                "standards": {"nist": "IA-5", "iso_27001": "A.8.24", "pci_dss": "Req 6.3.2"}
            }
        elif "639" in q or "862" in q or "idor" in q or "bola" in q:
            return {
                "cwe": "CWE-639 / CWE-862: Broken Object-Level Authorization (IDOR/BOLA)",
                "owasp": "A01:2021-Broken Access Control & API1:2023",
                "severity": "HIGH",
                "attack_vector": "Attacker alters record ID parameter (e.g. /api/invoices/1002) to view or update another user's private data.",
                "remediation": "Always validate that the authenticated user owns or has explicit permission to access the requested entity ID.",
                "standards": {"nist": "AC-3", "iso_27001": "A.8.26", "pci_dss": "Req 6.5.8"}
            }
        else:
            return {
                "query": q,
                "message": f"Security guidance for {q}: Refer to OWASP Top 10 and MITRE CWE catalogs. Ensure strict input validation, least-privilege authorization, and cryptographic parameterization."
            }

    def run_stdio(self):
        """Main loop reading from stdin and writing to stdout."""
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                request = json.loads(line)
                response = self.handle_request(request)
                if response:
                    sys.stdout.write(json.dumps(response) + "\n")
                    sys.stdout.flush()
            except Exception as e:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {str(e)}"}
                }
                sys.stdout.write(json.dumps(err_resp) + "\n")
                sys.stdout.flush()

def main():
    server = SecSkillMCPServer()
    server.run_stdio()

if __name__ == "__main__":
    main()

