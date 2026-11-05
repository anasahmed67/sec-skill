"""Abstract base class for all report generators."""
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional
from secskill.models import ScanReport

class BaseReporter(ABC):
    @abstractmethod
    def generate(self, report: ScanReport, output_path: Optional[Path] = None) -> str:
        """Generate report and optionally write to output_path."""
        pass
