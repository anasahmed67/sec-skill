"""AST and pattern-based static analysis engine."""
import re
import yaml
from pathlib import Path
from typing import List, Dict, Any
from secskill.analyzers.base import BaseAnalyzer
from secskill.models import ScanContext, Finding, Severity, Confidence

SEV_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFORMATIONAL": Severity.INFO,
    "INFO": Severity.INFO
}

class StaticAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str:
        return "StaticASTAnalyzer"

    def _load_yaml_rules(self) -> List[Dict[str, Any]]:
        rules = []
        rules_dir = Path(__file__).parent.parent / "rules"
        if rules_dir.is_dir():
            for yml_file in rules_dir.glob("*.yaml"):
                try:
                    with open(yml_file, "r", encoding="utf-8") as f:
                        data = yaml.safe_load(f)
                        if data and "rules" in data:
                            rules.extend(data["rules"])
                except Exception:
                    pass
        return rules

    def analyze(self, context: ScanContext) -> List[Finding]:
        findings = []
        root = Path(context.target_path)
        base_dir = root.parent if root.is_file() else root

        # Load YAML rules
        yaml_rules = self._load_yaml_rules()

        # Fallback default patterns if YAML rules fail to load
        fallback_patterns = [
            (r"eval\(", "SEC-PY-001", "Use of eval() detected", Severity.HIGH, "CWE-95"),
            (r"exec\(", "SEC-PY-002", "Use of exec() detected", Severity.HIGH, "CWE-95"),
            (r"subprocess\.(Popen|call|run)\(.*shell=True", "SEC-PY-003", "Command injection via shell=True", Severity.CRITICAL, "CWE-78"),
            (r"SELECT\s+.*FROM\s+.*WHERE.*(\+|\%|\.format|\$)", "SEC-SQL-001", "Possible SQL Injection", Severity.CRITICAL, "CWE-89"),
            (r"innerHTML\s*=", "SEC-JS-001", "Direct assignment to innerHTML (XSS)", Severity.MEDIUM, "CWE-79"),
        ]

        for file_rel in context.files:
            file_path = base_dir / file_rel
            if not file_path.is_file():
                continue
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                lines = content.splitlines()

                # 1. Match against rich YAML rules
                for r in yaml_rules:
                    rule_id = r.get("id", "SEC-RULE")
                    title = r.get("title", r.get("name", "Security Finding"))
                    sev_str = r.get("severity", "MEDIUM").upper()
                    sev = SEV_MAP.get(sev_str, Severity.MEDIUM)
                    cwe = r.get("cwe", "CWE-Generic")
                    owasp = r.get("owasp", None)
                    conf_val = r.get("confidence", 0.85)
                    conf = Confidence.HIGH if conf_val >= 0.85 else (Confidence.MEDIUM if conf_val >= 0.6 else Confidence.LOW)
                    remed = r.get("remediation", {})
                    remediation_desc = remed.get("description", str(remed)) if isinstance(remed, dict) else (str(remed) if remed else None)
                    patterns = r.get("patterns", [])

                    for line_idx, line in enumerate(lines, 1):
                        for pat in patterns:
                            try:
                                if re.search(pat, line):
                                    findings.append(
                                        Finding(
                                            id=f"{rule_id}-{file_rel}-{line_idx}",
                                            rule_id=rule_id,
                                            title=title,
                                            description=f"Rule {rule_id} triggered by pattern '{pat}'",
                                            severity=sev,
                                            confidence=conf,
                                            file_path=file_rel,
                                            line_number=line_idx,
                                            code_snippet=line.strip(),
                                            cwe_id=cwe,
                                            owasp_category=owasp,
                                            remediation=remediation_desc,
                                        )
                                    )
                                    break
                            except Exception:
                                pass

                # 2. Match fallbacks if no YAML rules loaded
                if not yaml_rules:
                    for line_idx, line in enumerate(lines, 1):
                        for pattern, rule_id, title, severity, cwe in fallback_patterns:
                            if re.search(pattern, line):
                                findings.append(
                                    Finding(
                                        id=f"{rule_id}-{file_rel}-{line_idx}",
                                        rule_id=rule_id,
                                        title=title,
                                        description=f"Pattern '{pattern}' matched at line {line_idx}",
                                        severity=severity,
                                        confidence=Confidence.HIGH,
                                        file_path=file_rel,
                                        line_number=line_idx,
                                        code_snippet=line.strip(),
                                        cwe_id=cwe,
                                    )
                                )
            except Exception:
                continue

        return findings
