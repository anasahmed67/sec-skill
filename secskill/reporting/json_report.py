"""JSON report generator."""
from pathlib import Path
from typing import Optional
from secskill.reporting.base import BaseReporter
from secskill.models import ScanReport

class JsonReporter(BaseReporter):
    def generate(self, report: ScanReport, output_path: Optional[Path] = None) -> str:
        content = report.model_dump_json(indent=2)
        if output_path:
            output_path.write_text(content, encoding="utf-8")
        return content
