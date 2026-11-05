"""Contextual review orchestration for triaging findings with LLMs."""
from typing import List, Optional
from secskill.models import Finding, ScanContext, TriageStatus
from secskill.llm.cache import LLMCache
from secskill.llm.ollama_provider import OllamaProvider
from secskill.llm.openai_provider import OpenAIProvider
from secskill.llm.anthropic_provider import AnthropicProvider

class ContextualReviewer:
    def __init__(self, provider_name: str = "ollama", model_name: Optional[str] = None):
        self.cache = LLMCache()
        self.provider_name = provider_name
        if provider_name == "openai":
            self.provider = OpenAIProvider(model=model_name or "gpt-4o")
        elif provider_name == "anthropic":
            self.provider = AnthropicProvider(model=model_name or "claude-3-5-sonnet-20241022")
        else:
            self.provider = OllamaProvider(model=model_name or "codellama")

    def triage_findings(self, findings: List[Finding], context: ScanContext) -> List[Finding]:
        for finding in findings:
            prompt = f"Review finding {finding.title} in {finding.file_path}:{finding.line_number}"
            cached = self.cache.get(prompt, self.provider_name)
            if cached:
                result = cached
            else:
                result = self.provider.review_finding(finding.model_dump(), finding.code_snippet or "")
                self.cache.set(prompt, self.provider_name, result)

            if result.get("status") == "CONFIRMED":
                finding.triage_status = TriageStatus.CONFIRMED
            elif result.get("status") == "FALSE_POSITIVE":
                finding.triage_status = TriageStatus.FALSE_POSITIVE
            finding.triage_reason = result.get("reason")
            finding.remediation = result.get("remediation")
        return findings
