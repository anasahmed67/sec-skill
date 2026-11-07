"""Analyzer for Model Context Protocol (MCP) server configuration security."""
import json
import re
import math
from pathlib import Path
from typing import List, Dict, Any, Tuple
from secskill.models import Severity
from secskill.agent_audit.models import (
    AgentFinding,
    AgentFindingCategory,
    McpServerInfo,
)

SECRET_KEY_NAMES = {
    "key", "secret", "token", "password", "auth", "apikey", "access_key",
    "private_key", "bearer", "credential", "jwt"
}

DANGEROUS_COMMANDS = {
    "bash", "sh", "zsh", "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh"
}

ROOT_PATH_INDICATORS = {
    "/", "\\", "c:\\", "c:/", "~", "$home", "%userprofile%", "/root", "/home"
}

def calculate_entropy(text: str) -> float:
    """Shannon entropy calculation."""
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())

def is_secret_value(value: str) -> bool:
    """Check if string looks like an actual hardcoded secret rather than variable expansion."""
    val = value.strip()
    if val.startswith("${") or val.startswith("$") or (val.startswith("%") and val.endswith("%")):
        return False
    if val.lower() in {"true", "false", "null", "none", "0", "1", "default", "development", "test"}:
        return False
    # Known secret prefixes
    if re.search(r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}", val):
        return True
    if re.search(r"sk-ant-[A-Za-z0-9_-]{20,}", val):
        return True
    if re.search(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}", val):
        return True
    if re.search(r"(?:AKIA|AGPA|AIDA|AROA)[A-Z0-9]{16}", val):
        return True
    # Generic high entropy string
    if len(val) >= 20 and calculate_entropy(val) >= 3.2:
        return True
    return False

class McpConfigAnalyzer:
    """Audits MCP configuration files for dangerous agency, credentials, and supply chain flaws."""

    def is_mcp_config(self, file_path: Path) -> bool:
        """Determine if a file is an MCP configuration file."""
        fname = file_path.name.lower()
        if fname in {
            "mcp.json", ".mcp.json", "claude_desktop_config.json",
            "cline_mcp_settings.json", "antigravity.json", "agent_config.json",
            "mcp_settings.json"
        }:
            return True
        if "mcp" in fname and fname.endswith(".json"):
            return True
        if file_path.parent.name.lower() in {".cursor", ".vscode"} and fname.endswith(".json"):
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                return "mcpServers" in content
            except Exception:
                return False
        return False

    def analyze_file(self, file_path: Path) -> Tuple[List[AgentFinding], List[McpServerInfo]]:
        findings: List[AgentFinding] = []
        servers_info: List[McpServerInfo] = []

        try:
            raw_text = file_path.read_text(encoding="utf-8", errors="ignore")
            # Strip simple JS style comments if present
            cleaned = re.sub(r"//.*?\n", "\n", raw_text)
            data = json.loads(cleaned)
        except Exception:
            return findings, servers_info

        mcp_servers = data.get("mcpServers")
        if not isinstance(mcp_servers, dict):
            # Also support flat dict where entries look like server definitions
            if isinstance(data, dict) and any(
                isinstance(v, dict) and ("command" in v or "url" in v) for v in data.values()
            ):
                mcp_servers = data
            else:
                return findings, servers_info

        rel_path = str(file_path).replace("\\", "/")
        finding_idx = 1

        for server_name, cfg in mcp_servers.items():
            if not isinstance(cfg, dict):
                continue

            command = str(cfg.get("command", "")).strip()
            args = [str(a) for a in cfg.get("args", [])]
            env = cfg.get("env", {}) if isinstance(cfg.get("env"), dict) else {}
            url = str(cfg.get("url", "")).strip()

            has_shell = False
            has_root = False
            has_raw_secrets = False
            is_pinned = True
            risk_level = Severity.LOW

            # 1. Check for hardcoded secrets in env
            for env_key, env_val in env.items():
                val_str = str(env_val)
                key_lower = env_key.lower()
                is_secret_name = any(k in key_lower for k in SECRET_KEY_NAMES)
                if is_secret_name and is_secret_value(val_str):
                    has_raw_secrets = True
                    risk_level = Severity.HIGH
                    masked = val_str[:4] + "..." + val_str[-4:] if len(val_str) > 8 else "***"
                    findings.append(AgentFinding(
                        id=f"AGENT-MCP-{finding_idx:03d}",
                        rule_id="MCP-CFG-001",
                        category=AgentFindingCategory.MCP_CONFIG,
                        title=f"Hardcoded Secret in MCP Server '{server_name}' Environment",
                        description=(
                            f"Server '{server_name}' configures environment variable '{env_key}' with a hardcoded secret token ({masked}). "
                            "Hardcoded credentials in MCP configs risk exposure across local processes, logs, and git commits."
                        ),
                        severity=Severity.HIGH,
                        file_path=rel_path,
                        line_number=1,
                        code_snippet=f'"{env_key}": "{masked}"',
                        owasp_llm="LLM02: Sensitive Information Disclosure",
                        mitre_atlas="AML.T0053: Exfiltration via Model Outputs",
                        cwe_id="CWE-798",
                        remediation=(
                            f"Replace the static secret with dynamic environment variable expansion: "
                            f'"{env_key}": "${{{env_key}}}"'
                        ),
                        suggested_fix=f'"${{{env_key}}}"',
                        metadata={"server_name": server_name, "env_var": env_key},
                    ))
                    finding_idx += 1

            # 2. Check for unbounded shell execution
            base_cmd = Path(command).name.lower()
            if base_cmd in DANGEROUS_COMMANDS:
                has_shell = True
                risk_level = Severity.CRITICAL
                findings.append(AgentFinding(
                    id=f"AGENT-MCP-{finding_idx:03d}",
                    rule_id="MCP-CFG-002",
                    category=AgentFindingCategory.MCP_CONFIG,
                    title=f"Excessive Agency: Unbounded Shell Access in MCP Server '{server_name}'",
                    description=(
                        f"MCP server '{server_name}' grants raw host shell execution via '{command}'. "
                        "An agent compromised via prompt injection or hallucinations can execute arbitrary OS commands on the host machine."
                    ),
                    severity=Severity.CRITICAL,
                    file_path=rel_path,
                    line_number=1,
                    code_snippet=f'"command": "{command}", "args": {json.dumps(args)}',
                    owasp_llm="LLM06: Excessive Agency",
                    mitre_atlas="AML.T0048: Insecure Output Handling",
                    cwe_id="CWE-78",
                    remediation=(
                        "Avoid exposing unrestricted shells directly as MCP servers. "
                        "Use scoped, domain-specific tools or run the shell in an isolated Docker sandbox with explicit approval gates."
                    ),
                    suggested_fix="Scope tool execution to isolated container or remove unbounded shell access.",
                    metadata={"server_name": server_name, "command": command},
                ))
                finding_idx += 1

            # 3. Check for root or home filesystem access
            for arg in args:
                raw_arg = arg.strip().lower()
                clean_arg = raw_arg.rstrip("/\\")
                if raw_arg in {"/", "\\", "~"} or clean_arg in ROOT_PATH_INDICATORS or clean_arg in {"c:", "d:"}:
                    has_root = True
                    if risk_level != Severity.CRITICAL:
                        risk_level = Severity.HIGH
                    findings.append(AgentFinding(
                        id=f"AGENT-MCP-{finding_idx:03d}",
                        rule_id="MCP-CFG-003",
                        category=AgentFindingCategory.MCP_CONFIG,
                        title=f"Unrestricted Root/Home Filesystem Access in MCP Server '{server_name}'",
                        description=(
                            f"MCP server '{server_name}' is mounted with root/home directory path '{arg}'. "
                            "This exposes user SSH keys (~/.ssh), credentials, and sensitive system files to autonomous agent tools."
                        ),
                        severity=Severity.HIGH,
                        file_path=rel_path,
                        line_number=1,
                        code_snippet=f'"args": {json.dumps(args)}',
                        owasp_llm="LLM06: Excessive Agency",
                        mitre_atlas="AML.T0048: Insecure Output Handling",
                        cwe_id="CWE-22",
                        remediation="Restrict allowed directory arguments to specific project subdirectories (e.g. './src' or './workspace').",
                        suggested_fix='"args": ["./workspace"]',
                        metadata={"server_name": server_name, "arg": arg},
                    ))
                    finding_idx += 1
                    break

            # 4. Check for unpinned remote execution
            if base_cmd in {"npx", "uvx", "pipx"}:
                for arg in args:
                    if arg.startswith("-") or "/" in arg and not arg.startswith("@"):
                        continue
                    # Match package names like `@modelcontextprotocol/server-filesystem` or `mcp-server-git`
                    if (arg.startswith("@") or "mcp" in arg.lower() or "server" in arg.lower()) and not arg.startswith("-"):
                        # If no version pinned (e.g. no @0.x or ==1.x)
                        has_version = False
                        if arg.startswith("@") and arg.count("@") >= 2:
                            has_version = True
                        elif not arg.startswith("@") and ("@" in arg or "==" in arg):
                            has_version = True

                        if not has_version:
                            is_pinned = False
                            if risk_level == Severity.LOW:
                                risk_level = Severity.MEDIUM
                            findings.append(AgentFinding(
                                id=f"AGENT-MCP-{finding_idx:03d}",
                                rule_id="MCP-CFG-004",
                                category=AgentFindingCategory.MCP_CONFIG,
                                title=f"Unpinned Remote Package Execution in MCP Server '{server_name}'",
                                description=(
                                    f"MCP server '{server_name}' executes package '{arg}' via {command} without an exact version pin. "
                                    "This creates a supply chain attack surface where package updates or typosquatting can execute malicious code."
                                ),
                                severity=Severity.MEDIUM,
                                file_path=rel_path,
                                line_number=1,
                                code_snippet=f'"{command}", {json.dumps(args)}',
                                owasp_llm="LLM05: Supply Chain Vulnerabilities",
                                mitre_atlas="AML.T0010: ML Supply Chain Compromise",
                                cwe_id="CWE-829",
                                remediation=f"Pin package '{arg}' to an explicit semantic version (e.g. '{arg}@1.0.0').",
                                suggested_fix=f'"{arg}@1.0.0"',
                                metadata={"server_name": server_name, "package": arg},
                            ))
                            finding_idx += 1

            # 5. Check for insecure plaintext HTTP transport
            if url:
                url_lower = url.lower()
                is_local = "localhost" in url_lower or "127.0.0.1" in url_lower or "::1" in url_lower
                if url_lower.startswith("http://") and not is_local:
                    findings.append(AgentFinding(
                        id=f"AGENT-MCP-{finding_idx:03d}",
                        rule_id="MCP-CFG-005",
                        category=AgentFindingCategory.MCP_CONFIG,
                        title=f"Insecure Plaintext Transport (HTTP) for Remote MCP Server '{server_name}'",
                        description=(
                            f"Remote MCP server '{server_name}' communicates over plaintext HTTP ({url}). "
                            "Agent tool calls and responses can be intercepted or tampered with via Man-in-the-Middle (MitM) attacks."
                        ),
                        severity=Severity.HIGH,
                        file_path=rel_path,
                        line_number=1,
                        code_snippet=f'"url": "{url}"',
                        owasp_llm="LLM02: Sensitive Information Disclosure",
                        mitre_atlas="AML.T0048: Insecure Output Handling",
                        cwe_id="CWE-319",
                        remediation="Migrate remote MCP endpoints to encrypted HTTPS transport.",
                        suggested_fix=f'"url": "{url.replace("http://", "https://")}"',
                        metadata={"server_name": server_name, "url": url},
                    ))
                    finding_idx += 1

            transport = "sse" if url else "stdio"
            servers_info.append(McpServerInfo(
                server_name=server_name,
                source_file=rel_path,
                command=command or url,
                args=args,
                has_shell_access=has_shell,
                has_filesystem_root=has_root,
                has_raw_env_secrets=has_raw_secrets,
                is_pinned=is_pinned,
                transport=transport,
                risk_level=risk_level,
            ))

        return findings, servers_info
