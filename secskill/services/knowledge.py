"""Domain security knowledge base and explainer service.

Provides MITRE CWE, OWASP Top 10, NIST SSDF, ISO 27001, and PCI-DSS contextual
guidance and attack vector simulations for vulnerabilities and security queries.
"""
from typing import Dict, Any

def explain_security_topic(query: str) -> Dict[str, Any]:
    """Retrieve detailed vulnerability taxonomy, attack simulations, and remediations.
    
    Args:
        query: CWE identifier, vulnerability title, or security keyword (e.g. 'CWE-89', 'sql').
        
    Returns:
        Structured dictionary containing CWE/OWASP mapping, attack simulation,
        concrete remediation steps, and international standards alignment.
    """
    q = query.lower().strip()
    
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
    elif "22" in q or "path" in q or "traversal" in q:
        return {
            "cwe": "CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
            "owasp": "A01:2021-Broken Access Control",
            "severity": "HIGH",
            "attack_vector": "Attacker injects '../' sequence to escape application web root and access sensitive files like /etc/passwd or application code.",
            "remediation": "Use os.path.abspath and verify that the target path begins with the allowed base directory before accessing the file.",
            "standards": {"nist": "AC-3", "iso_27001": "A.8.26", "pci_dss": "Req 6.5.8"}
        }
    elif "918" in q or "ssrf" in q:
        return {
            "cwe": "CWE-918: Server-Side Request Forgery (SSRF)",
            "owasp": "A10:2021-Server-Side Request Forgery",
            "severity": "HIGH",
            "attack_vector": "Attacker forces backend server to make outbound HTTP requests to cloud metadata services (169.254.169.254) or internal services.",
            "remediation": "Enforce strict allowlists of outbound destination hostnames and block RFC1918 private/loopback/link-local IP addresses.",
            "standards": {"nist": "SC-7", "iso_27001": "A.8.20", "pci_dss": "Req 6.4.3"}
        }
    elif "502" in q or "deserial" in q or "pickle" in q:
        return {
            "cwe": "CWE-502: Deserialization of Untrusted Data",
            "owasp": "A08:2021-Software and Data Integrity Failures",
            "severity": "CRITICAL",
            "attack_vector": "Attacker crafts malicious serialized object byte stream that executes arbitrary Python/Java bytecode during unpickling.",
            "remediation": "Never deserialize untrusted input with pickle, yaml.load, or Java ObjectInputStream. Use safe formats like JSON or Protocol Buffers.",
            "standards": {"nist": "SI-10", "iso_27001": "A.8.28", "pci_dss": "Req 6.5.2"}
        }
    else:
        return {
            "query": query,
            "message": f"Security guidance for {query}: Refer to OWASP Top 10 and MITRE CWE catalogs. Ensure strict input validation, least-privilege authorization, and cryptographic parameterization."
        }

