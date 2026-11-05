"""OASIS SARIF v2.1.0 report generator for GitHub Security integration."""
import json
from pathlib import Path
from typing import Optional
from secskill.reporting.base import BaseReporter
from secskill.models import ScanReport

class SarifReporter(BaseReporter):
    def generate(self, report: ScanReport, output_path: Optional[Path] = None) -> str:
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "SecSkill",
                            "version": "0.1.0",
                            "rules": []
                        }
                    },
                    "results": [
                        {
                            "ruleId": f.rule_id,
                            "level": "error" if f.severity in ["CRITICAL", "HIGH"] else "warning",
                            "message": {"text": f.description},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": f.file_path},
                                        "region": {"startLine": f.line_number}
                                    }
                                }
                            ]
                        }
                        for f in report.findings
                    ]
                }
            ]
        }
        content = json.dumps(sarif, indent=2)
        if output_path:
            output_path.write_text(content, encoding="utf-8")
        return content
