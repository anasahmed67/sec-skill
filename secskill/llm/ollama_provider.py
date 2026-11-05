"""Ollama local model provider implementation."""
import httpx
from typing import Dict, Any
from secskill.llm.base import BaseLLMProvider

class OllamaProvider(BaseLLMProvider):
    def __init__(self, model: str = "codellama", host: str = "http://localhost:11434"):
        self.model = model
        self.host = host

    def generate(self, prompt: str, system_prompt: str = "") -> str:
        try:
            r = httpx.post(f"{self.host}/api/generate", json={"model": self.model, "prompt": prompt, "stream": False}, timeout=10.0)
            if r.status_code == 200:
                return r.json().get("response", "")
        except Exception:
            pass
        return "Local Ollama model unavailable."

    def review_finding(self, finding_dict: Dict[str, Any], code_context: str) -> Dict[str, Any]:
        return {
            "status": "UNREVIEWED",
            "confidence": "MEDIUM",
            "reason": "Ollama local check fallback.",
            "remediation": "Review finding against secure coding standards."
        }
