"""Abstract base class for all security analyzers."""
from abc import ABC, abstractmethod
from typing import List
from secskill.models import ScanContext, Finding

class BaseAnalyzer(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the analyzer."""
        pass

    @abstractmethod
    def analyze(self, context: ScanContext) -> List[Finding]:
        """Execute analyzer against scan context and return findings."""
        pass
