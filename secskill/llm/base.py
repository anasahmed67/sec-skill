"""Abstract base class for LLM providers."""
from abc import ABC, abstractmethod
from typing import Dict, Any

class BaseLLMProvider(ABC):
    @abstractmethod
    def generate(self, prompt: str, system_prompt: str = "") -> str:
        """Send prompt to LLM and return text response."""
        pass

    @abstractmethod
    def review_finding(self, finding_dict: Dict[str, Any], code_context: str) -> Dict[str, Any]:
        """Contextual review of finding to confirm reachability and eliminate false positives."""
        pass
