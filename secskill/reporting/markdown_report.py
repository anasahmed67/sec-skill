"""GitHub PR comment and markdown summary reporter."""
from pathlib import Path
from typing import Optional
from secskill.reporting.base import BaseReporter
from secskill.models import ScanReport

class MarkdownReporter(BaseReporter):
    def generate(self, report: ScanReport, output_path: Optional[Path] = None) -> str:
        lines = [
            "# SecSkill Security Report",
            f"**Scan ID:** `{report.scan_id}` | **Target:** `{report.target_path}` | **Total Findings:** {len(report.findings)}",
            "",
            "| Severity | Rule ID | Location | Title |",
            "|---|---|---|---|",
        ]
        for f in report.findings:
            lines.append(f"| **{f.severity.value}** | `{f.rule_id}` | `{f.file_path}:{f.line_number}` | {f.title} |")

        content = "\n".join(lines)
        if output_path:
            output_path.write_text(content, encoding="utf-8")
        return content
