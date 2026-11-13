"""Analyzer for AI Agent Tool implementations and excessive agency risks."""
import ast
import re
from pathlib import Path
from typing import List, Optional
from secskill.models import Severity
from secskill.agent_audit.models import (
    AgentFinding,
    AgentFindingCategory,
)

DESTRUCTIVE_FILE_OPS = {"remove", "unlink", "rmdir", "rmtree"}
SUBPROCESS_CALLS = {"system", "run", "popen", "call", "check_output", "check_call"}
HTTP_CLIENT_FUNCS = {"get", "post", "put", "delete", "request", "urlopen"}

def is_tool_candidate(path: Path) -> bool:
    """Check if file likely contains agent tools or MCP server implementations."""
    name = path.name.lower()
    parent = path.parent.name.lower()
    tool_keywords = {"tool", "agent", "mcp", "skill", "plugin", "action", "executor"}
    if any(k in name for k in tool_keywords) or any(k in parent for k in tool_keywords):
        return True
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
        return any(
            marker in content
            for marker in ["@tool", "mcp.tool", "CallToolRequestSchema", "server.tool", "addTool", "agent"]
        )
    except Exception:
        return False

class PythonToolVisitor(ast.NodeVisitor):
    """AST visitor searching for excessive agency and unsafe operations in agent tools."""

    def __init__(self, file_path: str, source_lines: List[str]):
        self.file_path = file_path
        self.source_lines = source_lines
        self.findings: List[AgentFinding] = []
        self._finding_count = 0
        self.current_function: Optional[str] = None
        self.current_is_tool = False
        self.has_confirmation_check = False

    def _next_id(self) -> str:
        self._finding_count += 1
        return f"AGENT-TOOL-{self._finding_count:03d}"

    def _get_snippet(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def visit_FunctionDef(self, node: ast.FunctionDef):
        prev_func = self.current_function
        prev_is_tool = self.current_is_tool
        prev_conf = self.has_confirmation_check

        self.current_function = node.name
        # Check decorators for @tool, @mcp.tool, etc.
        decorator_names = []
        for d in node.decorator_list:
            if isinstance(d, ast.Name):
                decorator_names.append(d.id.lower())
            elif isinstance(d, ast.Attribute):
                decorator_names.append(d.attr.lower())
            elif isinstance(d, ast.Call):
                if isinstance(d.func, ast.Name):
                    decorator_names.append(d.func.id.lower())
                elif isinstance(d.func, ast.Attribute):
                    decorator_names.append(d.func.attr.lower())

        is_tool = any("tool" in dn or "skill" in dn or "action" in dn for dn in decorator_names)
        if not is_tool:
            # Check function name or docstring
            fn_lower = node.name.lower()
            if fn_lower.startswith(("tool_", "execute_", "run_tool_", "mcp_")):
                is_tool = True
            elif "tool" in self.file_path.lower() or "mcp" in self.file_path.lower():
                is_tool = True

        self.current_is_tool = is_tool

        # Check if function body contains approval / confirmation patterns
        func_source = "\n".join(self.source_lines[node.lineno - 1 : getattr(node, "end_lineno", node.lineno)])
        self.has_confirmation_check = any(
            gate in func_source.lower()
            for gate in ["confirm", "approval", "ask_user", "dry_run", "human_in_the_loop", "prompt_user"]
        )

        self.generic_visit(node)

        self.current_function = prev_func
        self.current_is_tool = prev_is_tool
        self.has_confirmation_check = prev_conf

    def visit_Call(self, node: ast.Call):
        if not self.current_is_tool:
            self.generic_visit(node)
            return

        func_name = ""
        attr_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
            attr_name = node.func.attr
            if isinstance(node.func.value, ast.Name):
                func_name = f"{node.func.value.id}.{node.func.attr}"

        lineno = node.lineno
        snippet = self._get_snippet(lineno)

        # 1. Dynamic code execution (eval, exec, compile)
        if func_name in {"eval", "exec", "compile"}:
            self.findings.append(AgentFinding(
                id=self._next_id(),
                rule_id="AGENT-TOOL-001",
                category=AgentFindingCategory.AGENT_TOOL,
                title=f"Dynamic Code Evaluation ({func_name}) in Agent Tool '{self.current_function}'",
                description=(
                    f"Agent tool '{self.current_function}' calls dynamic code evaluation function '{func_name}()'. "
                    "An autonomous agent instructed via prompt injection can pass arbitrary code to escape sandbox boundaries and compromise the host."
                ),
                severity=Severity.CRITICAL,
                file_path=self.file_path,
                line_number=lineno,
                code_snippet=snippet,
                owasp_llm="LLM06: Excessive Agency",
                mitre_atlas="AML.T0048: Insecure Output Handling",
                cwe_id="CWE-94",
                remediation=(
                    "Do not allow LLM tools to evaluate arbitrary code with eval/exec. "
                    "Use deterministic parsers, abstract syntax validation, or sandboxed isolated microVMs."
                ),
                suggested_fix="# Replace eval/exec with deterministic AST or sandboxed runtime",
                metadata={"function": self.current_function, "eval_call": func_name},
            ))

        # 2. Subprocess and shell execution
        is_subprocess = (
            func_name in {"os.system", "subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_output"}
            or (attr_name in SUBPROCESS_CALLS and "subprocess" in func_name)
        )
        if is_subprocess:
            # Check for shell=True
            has_shell_true = False
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    has_shell_true = True

            if has_shell_true:
                self.findings.append(AgentFinding(
                    id=self._next_id(),
                    rule_id="AGENT-TOOL-002",
                    category=AgentFindingCategory.AGENT_TOOL,
                    title=f"Excessive Agency: Subprocess with shell=True in Agent Tool '{self.current_function}'",
                    description=(
                        f"Agent tool '{self.current_function}' executes OS subprocess with shell=True. "
                        "Adversarial input or prompt injection will trigger OS command injection on the host."
                    ),
                    severity=Severity.CRITICAL,
                    file_path=self.file_path,
                    line_number=lineno,
                    code_snippet=snippet,
                    owasp_llm="LLM06: Excessive Agency",
                    mitre_atlas="AML.T0048: Insecure Output Handling",
                    cwe_id="CWE-78",
                    remediation="Change shell=True to shell=False and pass arguments as an explicit validated list.",
                    suggested_fix="shell=False",
                    metadata={"function": self.current_function, "shell_true": True},
                ))
            elif not self.has_confirmation_check:
                self.findings.append(AgentFinding(
                    id=self._next_id(),
                    rule_id="AGENT-TOOL-003",
                    category=AgentFindingCategory.AGENT_TOOL,
                    title=f"Excessive Agency: Subprocess in Agent Tool '{self.current_function}' Missing Human Confirmation Gate",
                    description=(
                        f"Agent tool '{self.current_function}' triggers host process execution ({func_name}) "
                        "without a human-in-the-loop confirmation check or dry-run validation flag."
                    ),
                    severity=Severity.HIGH,
                    file_path=self.file_path,
                    line_number=lineno,
                    code_snippet=snippet,
                    owasp_llm="LLM06: Excessive Agency",
                    mitre_atlas="AML.T0048: Insecure Output Handling",
                    cwe_id="CWE-862",
                    remediation="Wrap destructive or system-level tool invocations with an explicit user confirmation prompt or approval gate.",
                    suggested_fix="if not confirm_action(command): return 'Action rejected by user'",
                    metadata={"function": self.current_function},
                ))

        # 3. Destructive file operations
        is_file_delete = (
            func_name in {"os.remove", "os.unlink", "os.rmdir", "shutil.rmtree"}
            or (isinstance(node.func, ast.Attribute) and node.func.attr in DESTRUCTIVE_FILE_OPS)
        )
        if is_file_delete and not self.has_confirmation_check:
            self.findings.append(AgentFinding(
                id=self._next_id(),
                rule_id="AGENT-TOOL-004",
                category=AgentFindingCategory.AGENT_TOOL,
                title=f"Excessive Agency: Destructive File Operation ({func_name}) in Agent Tool '{self.current_function}'",
                description=(
                    f"Agent tool '{self.current_function}' performs file deletion or directory removal ({func_name}) "
                    "without path confinement checks (is_relative_to) or confirmation safeguards."
                ),
                severity=Severity.HIGH,
                file_path=self.file_path,
                line_number=lineno,
                code_snippet=snippet,
                owasp_llm="LLM06: Excessive Agency",
                mitre_atlas="AML.T0048: Insecure Output Handling",
                cwe_id="CWE-22",
                remediation="Canonicalize the path and verify it is strictly within the permitted workspace directory before deletion.",
                suggested_fix="target_path.resolve().is_relative_to(allowed_root)",
                metadata={"function": self.current_function, "file_op": func_name},
            ))

        # 4. SSRF / Arbitrary Network Fetch
        is_http_call = (
            func_name.startswith(("requests.", "httpx.", "urllib.request."))
            or (isinstance(node.func, ast.Attribute) and node.func.attr in HTTP_CLIENT_FUNCS and any(h in func_name for h in ["http", "client", "session", "req"]))
        )
        if is_http_call:
            # Check if function validates IP or metadata
            func_source = "\n".join(self.source_lines[max(0, lineno - 15) : lineno])
            has_ssrf_guard = any(g in func_source.lower() for g in ["169.254", "localhost", "127.0.0.1", "is_private", "block_internal"])
            if not has_ssrf_guard:
                self.findings.append(AgentFinding(
                    id=self._next_id(),
                    rule_id="AGENT-TOOL-005",
                    category=AgentFindingCategory.AGENT_TOOL,
                    title=f"SSRF Risk in Agent Network Tool '{self.current_function}'",
                    description=(
                        f"Agent tool '{self.current_function}' performs network requests ({func_name}) "
                        "without filtering internal IP addresses or cloud metadata endpoints (e.g. 169.254.169.254). "
                        "An agent instructed via prompt injection can exfiltrate internal services and IAM credentials."
                    ),
                    severity=Severity.HIGH,
                    file_path=self.file_path,
                    line_number=lineno,
                    code_snippet=snippet,
                    owasp_llm="LLM08: Vector and Embedding / SSRF",
                    mitre_atlas="AML.T0053: Exfiltration via Model Outputs",
                    cwe_id="CWE-918",
                    remediation="Validate URL target host: block private RFC 1918 subnets, loopback addresses, and cloud metadata (169.254.169.254).",
                    suggested_fix="verify_safe_external_url(target_url)",
                    metadata={"function": self.current_function},
                ))

        # 5. Raw SQL Execution in Agent Tools
        is_sql_exec = (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {"execute", "raw"}
            and any(db in func_name.lower() for db in ["cursor", "session", "db", "conn"])
        )
        if is_sql_exec:
            # Check if query argument is an f-string or string formatting
            if node.args and isinstance(node.args[0], (ast.JoinedStr, ast.BinOp)):
                self.findings.append(AgentFinding(
                    id=self._next_id(),
                    rule_id="AGENT-TOOL-006",
                    category=AgentFindingCategory.AGENT_TOOL,
                    title=f"Raw SQL Injection in Agent Database Tool '{self.current_function}'",
                    description=(
                        f"Agent tool '{self.current_function}' executes database query using string interpolation. "
                        "LLM output must never be interpolated directly into SQL statements."
                    ),
                    severity=Severity.HIGH,
                    file_path=self.file_path,
                    line_number=lineno,
                    code_snippet=snippet,
                    owasp_llm="LLM06: Excessive Agency",
                    mitre_atlas="AML.T0048: Insecure Output Handling",
                    cwe_id="CWE-89",
                    remediation="Use parameterized queries with driver placeholders (? or %s).",
                    suggested_fix="cursor.execute('SELECT * FROM table WHERE id = ?', (param,))",
                    metadata={"function": self.current_function},
                ))

        self.generic_visit(node)


class AgentToolAnalyzer:
    """Discovers and audits Agent Tool implementations in Python and JS/TS."""

    def analyze_file(self, file_path: Path) -> List[AgentFinding]:
        findings: List[AgentFinding] = []
        suffix = file_path.suffix.lower()

        if suffix == ".py":
            findings.extend(self._analyze_python(file_path))
        elif suffix in {".js", ".ts", ".mjs", ".cjs", ".tsx"}:
            findings.extend(self._analyze_javascript(file_path))

        return findings

    def _analyze_python(self, file_path: Path) -> List[AgentFinding]:
        try:
            source = file_path.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source, filename=str(file_path))
        except Exception:
            return []

        rel_path = str(file_path).replace("\\", "/")
        lines = source.splitlines()
        visitor = PythonToolVisitor(rel_path, lines)
        visitor.visit(tree)
        return visitor.findings

    def _analyze_javascript(self, file_path: Path) -> List[AgentFinding]:
        findings: List[AgentFinding] = []
        try:
            source = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return []

        rel_path = str(file_path).replace("\\", "/")
        lines = source.splitlines()

        for idx, line in enumerate(lines, start=1):
            stripped = line.strip()
            # 1. Dynamic code evaluation in JS tool
            if re.search(r"\b(?:eval|Function|vm\.runInContext)\s*\(", stripped):
                findings.append(AgentFinding(
                    id=f"AGENT-TOOL-JS-{len(findings) + 1:03d}",
                    rule_id="AGENT-TOOL-001",
                    category=AgentFindingCategory.AGENT_TOOL,
                    title="Dynamic Code Evaluation in JavaScript Agent Tool",
                    description=(
                        "Detected dynamic code evaluation ('eval' or 'Function') in agent tool. "
                        "Untrusted agent input can execute arbitrary JavaScript in the runtime process."
                    ),
                    severity=Severity.CRITICAL,
                    file_path=rel_path,
                    line_number=idx,
                    code_snippet=stripped,
                    owasp_llm="LLM06: Excessive Agency",
                    mitre_atlas="AML.T0048: Insecure Output Handling",
                    cwe_id="CWE-94",
                    remediation="Avoid eval/Function. Use deterministic JSON or AST handlers.",
                    suggested_fix="// Replace dynamic eval with structured parser",
                ))

            # 2. child_process.exec without confirmation
            if re.search(r"\b(?:child_process\.)?(?:exec|execSync)\s*\(", stripped):
                findings.append(AgentFinding(
                    id=f"AGENT-TOOL-JS-{len(findings) + 1:03d}",
                    rule_id="AGENT-TOOL-002",
                    category=AgentFindingCategory.AGENT_TOOL,
                    title="Excessive Agency: Subprocess Shell Execution in JavaScript Tool",
                    description=(
                        "Tool invokes child_process.exec() which spawns a system shell. "
                        "Unescaped metacharacters in agent parameters lead to remote command injection."
                    ),
                    severity=Severity.HIGH,
                    file_path=rel_path,
                    line_number=idx,
                    code_snippet=stripped,
                    owasp_llm="LLM06: Excessive Agency",
                    mitre_atlas="AML.T0048: Insecure Output Handling",
                    cwe_id="CWE-78",
                    remediation="Use child_process.execFile() or spawn() with explicit argument array and no shell.",
                    suggested_fix="execFile(cmd, [arg1, arg2])",
                ))

        return findings

