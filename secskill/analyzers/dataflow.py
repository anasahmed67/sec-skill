"""Taint dataflow tracking (Source to Sink analysis)."""
import re
from pathlib import Path
from typing import List
from secskill.analyzers.base import BaseAnalyzer
from secskill.models import ScanContext, Finding, Severity, Confidence

class DataflowAnalyzer(BaseAnalyzer):
    @property
    def name(self) -> str:
        return "DataflowAnalyzer"

    def analyze(self, context: ScanContext) -> List[Finding]:
        findings = []
        root = Path(context.target_path)
        base_dir = root.parent if root.is_file() else root
        
        sources = [
            r"request\.args",
            r"request\.form",
            r"request\.json",
            r"request\.GET",
            r"request\.POST",
            r"req\.query",
            r"req\.body",
            r"req\.params",
            r"sys\.argv",
        ]
        sinks = [
            (r"cursor\.execute\s*\(\s*f[\"']", "SQL Injection via f-string query in cursor.execute"),
            (r"cursor\.execute\s*\([^,)]*\%", "SQL Injection via % formatting in cursor.execute"),
            (r"cursor\.execute\s*\([^,)]*\.format\(", "SQL Injection via .format() in cursor.execute"),
            (r"open\s*\([^\n)]*request\.", "Path Traversal via direct request input in open()"),
            (r"os\.system\s*\([^\n)]*request\.", "Command Injection via request input in os.system()"),
            (r"res\.send\s*\(\s*`[^`]*\$\{.*req\.", "Cross-Site Scripting via template literal in res.send()"),
        ]

        for file_rel in context.files:
            file_path = base_dir / file_rel
            if not file_path.is_file():
                continue
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                has_source = any(re.search(src, content) for src in sources)
                
                # Check for direct f-string query assignments linked to cursor
                has_fstring_query = bool(re.search(r"query\s*=\s*f[\"']SELECT", content, re.IGNORECASE))

                for line_idx, line in enumerate(content.splitlines(), 1):
                    # Direct sink matches
                    for sink_regex, desc in sinks:
                        if re.search(sink_regex, line):
                            findings.append(
                                Finding(
                                    id=f"TAINT-{file_rel}-{line_idx}",
                                    rule_id="DATAFLOW-TAINT-001",
                                    title="Untrusted Dataflow to Sensitive Sink",
                                    description=desc,
                                    severity=Severity.HIGH,
                                    confidence=Confidence.HIGH,
                                    file_path=file_rel,
                                    line_number=line_idx,
                                    code_snippet=line.strip(),
                                    cwe_id="CWE-89" if "SQL" in desc else "CWE-20",
                                )
                            )
                    # If query is f-string and executed on this line without tuple parameters
                    if has_fstring_query and "cursor.execute(query)" in line.replace(" ", ""):
                        findings.append(
                            Finding(
                                id=f"TAINT-{file_rel}-{line_idx}",
                                rule_id="DATAFLOW-TAINT-001",
                                title="SQL Injection via Interpolated Query Variable",
                                description="f-string SQL query executed without driver parameterization.",
                                severity=Severity.CRITICAL,
                                confidence=Confidence.HIGH,
                                file_path=file_rel,
                                line_number=line_idx,
                                code_snippet=line.strip(),
                                cwe_id="CWE-89",
                            )
                        )
            except Exception:
                continue
        return findings
