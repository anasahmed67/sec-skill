"""Rich terminal reporter."""
from pathlib import Path
from typing import Optional
from rich.console import Console
from rich.table import Table
from secskill.reporting.base import BaseReporter
from secskill.models import ScanReport

class ConsoleReporter(BaseReporter):
    def generate(self, report: ScanReport, output_path: Optional[Path] = None) -> str:
        console = Console()
        table = Table(title=f"SecSkill Scan Summary (Found: {len(report.findings)})")
        table.add_column("Severity", style="bold")
        table.add_column("Rule ID", style="cyan")
        table.add_column("Location")
        table.add_column("Title")

        for f in report.findings:
            color = {
                "CRITICAL": "red",
                "HIGH": "bright_red",
                "MEDIUM": "yellow",
                "LOW": "blue",
                "INFO": "dim",
            }.get(f.severity.value, "white")
            table.add_row(f"[{color}]{f.severity.value}[/{color}]", f.rule_id, f"{f.file_path}:{f.line_number}", f.title)

        console.print(table)
        return "Console output generated."
