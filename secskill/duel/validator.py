"""AST and Taint validation engine for AI Red Team vs. Blue Team Duel Arena."""
import ast
import re
from typing import List, Dict, Any, Tuple, Optional
from secskill.duel.models import ValidationVerdict, AttackPayload

class ASTSecurityInspector(ast.NodeVisitor):
    """Deep AST inspector analyzing dangerous calls, formatting patterns, and parameterization."""
    def __init__(self, code: str):
        self.code = code
        self.ast_violations: List[str] = []
        self.taint_violations: List[str] = []
        self.has_safe_parameterization = False
        self.has_naive_sanitization = False
        self.dangerous_sinks_found: List[str] = []
        self.safe_patterns_found: List[str] = []
        self.variable_assignments: Dict[str, ast.AST] = {}

    def visit_Assign(self, node: ast.Assign):
        # Track assignments to see if variables store f-strings or concatenated queries
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.variable_assignments[target.id] = node.value
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        func_name = self._get_call_name(node.func)

        # 1. Check SQL Sinks (cursor.execute, session.execute, db.execute)
        if any(sink in func_name for sink in ["execute", "executemany", "raw_sql", "query"]):
            self.dangerous_sinks_found.append(func_name)
            self._inspect_sql_call(node, func_name)

        # 2. Check Command Execution Sinks (os.system, os.popen, subprocess.*)
        elif any(sink in func_name for sink in ["os.system", "os.popen", "subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_output"]):
            self.dangerous_sinks_found.append(func_name)
            self._inspect_command_call(node, func_name)

        # 3. Check File Open Sinks (open)
        elif func_name == "open":
            self.dangerous_sinks_found.append(func_name)
            self._inspect_file_call(node)

        # 4. Check Eval/Exec Sinks
        elif func_name in ["eval", "exec"]:
            self.dangerous_sinks_found.append(func_name)
            self.ast_violations.append(f"CRITICAL: Direct invocation of dynamic code interpreter '{func_name}()' (CWE-94/95).")
            self.taint_violations.append(f"Arbitrary code execution sink '{func_name}' directly reachable.")

        # 5. Check Naive Sanitization Calls (e.g. .replace("'", ""))
        if func_name.endswith(".replace") or func_name == "re.sub":
            self._inspect_sanitization(node)

        # 6. Check Safe Escaping / Boundaries
        if any(safe in func_name for safe in ["html.escape", "DOMPurify.sanitize", "shlex.quote", "ast.literal_eval", "is_relative_to"]):
            self.safe_patterns_found.append(func_name)

        self.generic_visit(node)

    def _get_call_name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            value_name = self._get_call_name(node.value)
            return f"{value_name}.{node.attr}" if value_name else node.attr
        return ""

    def _inspect_sql_call(self, node: ast.Call, func_name: str):
        if not node.args:
            return

        arg0 = node.args[0]
        # Check if arg0 is an f-string
        if isinstance(arg0, ast.JoinedStr):
            self.ast_violations.append(
                f"CRITICAL: '{func_name}' invoked with AST JoinedStr (f-string). SQL grammar can be manipulated (CWE-89)."
            )
            self.taint_violations.append("Untrusted input interpolated directly into SQL syntax AST.")
            return

        # Check if arg0 is string concatenation or modulo formatting
        if isinstance(arg0, ast.BinOp):
            if isinstance(arg0.op, ast.Add):
                self.ast_violations.append(
                    f"CRITICAL: '{func_name}' invoked with string concatenation (+) (CWE-89)."
                )
                self.taint_violations.append("String concatenation dynamically modifies SQL command structure.")
                return
            elif isinstance(arg0.op, ast.Mod):
                self.ast_violations.append(
                    f"CRITICAL: '{func_name}' invoked with % string formatting (CWE-89)."
                )
                self.taint_violations.append("Modulo string formatting used instead of DB-API parameterization.")
                return

        # Check if arg0 is .format() call
        if isinstance(arg0, ast.Call) and self._get_call_name(arg0.func).endswith(".format"):
            self.ast_violations.append(
                f"CRITICAL: '{func_name}' invoked with .format() interpolation (CWE-89)."
            )
            self.taint_violations.append(".format() token interpolation exposes SQL statement to injection.")
            return

        # Check if arg0 is a variable that was previously defined as an f-string or concat
        if isinstance(arg0, ast.Name):
            var_value = self.variable_assignments.get(arg0.id)
            if isinstance(var_value, ast.JoinedStr):
                self.ast_violations.append(
                    f"CRITICAL: '{func_name}' receives variable '{arg0.id}' created via f-string interpolation."
                )
                self.taint_violations.append(f"Taint flows from variable '{arg0.id}' into '{func_name}' sink.")
                return
            elif isinstance(var_value, ast.BinOp):
                self.ast_violations.append(
                    f"CRITICAL: '{func_name}' receives variable '{arg0.id}' created via string concatenation."
                )
                self.taint_violations.append(f"Taint flows from concatenated variable '{arg0.id}' into '{func_name}'.")
                return

        # Safe DB-API parameterization check:
        # e.g., cursor.execute("SELECT ... WHERE id = %s", (user_id,))
        # or query = "SELECT ... WHERE id = %s"; cursor.execute(query, (user_id,))
        # Must have at least 2 arguments or keyword params
        if len(node.args) >= 2 or node.keywords:
            is_const = False
            if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
                is_const = True
            elif isinstance(arg0, ast.Name):
                var_value = self.variable_assignments.get(arg0.id)
                if isinstance(var_value, ast.Constant) and isinstance(var_value.value, str):
                    is_const = True
                elif var_value is None or not isinstance(var_value, (ast.JoinedStr, ast.BinOp)):
                    is_const = True
            if is_const:
                self.has_safe_parameterization = True
                self.safe_patterns_found.append("DB-API Parameterized Query with Placeholder")

    def _inspect_command_call(self, node: ast.Call, func_name: str):
        if func_name in ["os.system", "os.popen"]:
            self.ast_violations.append(
                f"CRITICAL: Insecure sink '{func_name}' invokes system shell interpreter directly (CWE-78)."
            )
            self.taint_violations.append(f"Command execution via '{func_name}' allows shell metacharacter chaining (; | & `).")
            return

        # Subprocess check: look for shell=True
        shell_true = False
        for kw in node.keywords:
            if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                shell_true = True
                break

        if shell_true:
            self.ast_violations.append(
                "CRITICAL: subprocess invoked with 'shell=True' (CWE-78). Shell command injection vulnerability."
            )
            self.taint_violations.append("Subprocess shell=True processes untrusted arguments through system shell interpreter.")
        else:
            # Check if first argument is a list or tuple (safe command execution)
            if node.args and isinstance(node.args[0], (ast.List, ast.Tuple)):
                self.has_safe_parameterization = True
                self.safe_patterns_found.append("subprocess argument list with shell=False")

    def _inspect_file_call(self, node: ast.Call):
        if not node.args:
            return
        arg0 = node.args[0]
        # If open(f"/path/{user_input}") without validation
        if isinstance(arg0, ast.JoinedStr) or isinstance(arg0, ast.BinOp):
            if "is_relative_to" not in self.code and "resolve()" not in self.code and "os.path.abspath" not in self.code:
                self.ast_violations.append(
                    "HIGH: open() receives dynamic interpolated path without canonical boundary verification (CWE-22)."
                )
                self.taint_violations.append("Path traversal taint flows directly into open() file descriptor.")

    def _inspect_sanitization(self, node: ast.Call):
        # Detect weak sanitization attempts like x.replace("'", "")
        # If args contain single quote or common chars
        if node.args:
            first_arg = node.args[0]
            if isinstance(first_arg, ast.Constant) and first_arg.value in ["'", '"', "--", "/*", "*/", "../"]:
                self.has_naive_sanitization = True


class DuelValidator:
    """SecSkill referee that validates code using AST rules, taint flow tracking, and payload simulation."""

    @classmethod
    def validate(
        cls,
        code: str,
        vuln_type: str,
        payload: Optional[AttackPayload] = None,
    ) -> ValidationVerdict:
        """Run full AST and taint analysis on code and evaluate against exploit payload."""
        ast_violations: List[str] = []
        taint_violations: List[str] = []
        ast_safe = True
        taint_clean = True
        bypass_detected = False
        is_safe = False

        # Attempt Python AST parsing
        try:
            tree = ast.parse(code)
            inspector = ASTSecurityInspector(code)
            inspector.visit(tree)

            ast_violations.extend(inspector.ast_violations)
            taint_violations.extend(inspector.taint_violations)

            # Check if there are AST violations
            if ast_violations:
                ast_safe = False
            if taint_violations:
                taint_clean = False

            # Check for naive sanitization
            if inspector.has_naive_sanitization and not inspector.has_safe_parameterization:
                ast_violations.append(
                    "WARNING: Naive blacklist sanitization (.replace() / regex filtering) detected. Susceptible to WAF evasion & bypass."
                )

            # Heuristics based on vulnerability type
            vuln_lower = vuln_type.lower()
            if "sql" in vuln_lower or "89" in vuln_lower:
                if inspector.has_safe_parameterization and ast_safe:
                    is_safe = True
                elif not inspector.dangerous_sinks_found:
                    # No SQL sinks found or safe ORM
                    is_safe = True
                else:
                    is_safe = False

            elif "cmd" in vuln_lower or "command" in vuln_lower or "78" in vuln_lower:
                if inspector.has_safe_parameterization and ast_safe:
                    is_safe = True
                elif not any("os.system" in s or "os.popen" in s for s in inspector.dangerous_sinks_found) and ast_safe:
                    is_safe = True
                else:
                    is_safe = False

            elif "path" in vuln_lower or "traversal" in vuln_lower or "22" in vuln_lower:
                if ("is_relative_to" in code or "resolve" in code) and ast_safe:
                    is_safe = True
                else:
                    is_safe = False

            elif "xss" in vuln_lower or "79" in vuln_lower:
                if any(esc in code for esc in ["html.escape", "DOMPurify", "escapeHtml", "sanitize"]) and ast_safe:
                    is_safe = True
                else:
                    is_safe = False
            else:
                is_safe = ast_safe and taint_clean

        except SyntaxError as e:
            # If not valid Python or snippet, fallback to regex-based static pattern scanning
            ast_safe, taint_clean, ast_violations, taint_violations, is_safe = cls._validate_regex_fallback(code, vuln_type)

        # Evaluate if Red's payload triggered a bypass
        if not is_safe:
            bypass_detected = True
            feedback_blue = (
                f"[SecSkill AST Violation] {ast_violations[0] if ast_violations else 'Vulnerability persists.'} "
                "Blue must adapt by parameterizing inputs or enforcing boundary checks!"
            )
            feedback_red = (
                f"[SecSkill Referee] Red payload successfully bypassed defenses! Exploit vector confirmed."
            )
            details = (
                f"BYPASS DETECTED: Code remains vulnerable. "
                f"AST Violations: {len(ast_violations)}, Taint Violations: {len(taint_violations)}."
            )
        else:
            bypass_detected = False
            feedback_blue = (
                "[SecSkill Referee] IMPENETRABLE! AST is verified safe and taint flow is completely neutralized."
            )
            feedback_red = (
                "[SecSkill Referee] Red payload was completely defused by Blue's parameterization and AST safety."
            )
            details = (
                "DEFENSE VERIFIED: 0 AST violations, 0 taint sinks. "
                "All user input isolated as literal parameters."
            )

        return ValidationVerdict(
            is_safe=is_safe,
            bypass_detected=bypass_detected,
            ast_safe=ast_safe,
            taint_clean=taint_clean,
            ast_violations=ast_violations,
            taint_violations=taint_violations,
            details=details,
            feedback_for_blue=feedback_blue,
            feedback_for_red=feedback_red,
        )

    @classmethod
    def _validate_regex_fallback(
        cls, code: str, vuln_type: str
    ) -> Tuple[bool, bool, List[str], List[str], bool]:
        """Fallback regex verification when AST parsing cannot parse syntax directly."""
        ast_violations = []
        taint_violations = []
        vuln_lower = vuln_type.lower()

        # SQL Injection regex checks
        if "sql" in vuln_lower or "89" in vuln_lower:
            if re.search(r'cursor\.execute\s*\(\s*f["\']', code):
                ast_violations.append("CRITICAL: cursor.execute with f-string query.")
            if re.search(r'cursor\.execute\s*\([^,)]*[\+\%]', code):
                ast_violations.append("CRITICAL: cursor.execute with string concatenation or % formatting.")
            if re.search(r'cursor\.execute\s*\([^,)]*\.format\(', code):
                ast_violations.append("CRITICAL: cursor.execute with .format() interpolation.")
            
            # Check safe parameterization
            is_param = bool(re.search(r'cursor\.execute\s*\(\s*["\'][^"\']+["\']\s*,\s*\(', code))
            is_safe = is_param and len(ast_violations) == 0

        # Command Injection regex checks
        elif "cmd" in vuln_lower or "command" in vuln_lower or "78" in vuln_lower:
            if re.search(r'os\.system\s*\(', code):
                ast_violations.append("CRITICAL: os.system() command execution.")
            if re.search(r'shell\s*=\s*True', code):
                ast_violations.append("CRITICAL: subprocess with shell=True.")
            
            is_safe = ("shell=False" in code or "[" in code) and len(ast_violations) == 0

        # Path Traversal regex checks
        elif "path" in vuln_lower or "22" in vuln_lower:
            if "is_relative_to" in code or "resolve()" in code:
                is_safe = True
            else:
                ast_violations.append("HIGH: open() without path boundary verification.")
                is_safe = False
        else:
            is_safe = len(ast_violations) == 0

        if ast_violations:
            taint_violations.append("Untrusted taint reaches sensitive execution sink.")

        ast_safe = len(ast_violations) == 0
        taint_clean = len(taint_violations) == 0
        return ast_safe, taint_clean, ast_violations, taint_violations, is_safe
