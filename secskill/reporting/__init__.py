"""Report generators and reporter factory for Console, SARIF, JSON, Markdown, and HTML."""
from typing import Dict, Type
from secskill.reporting.base import BaseReporter
from secskill.reporting.console_report import ConsoleReporter
from secskill.reporting.sarif_report import SarifReporter
from secskill.reporting.json_report import JsonReporter
from secskill.reporting.markdown_report import MarkdownReporter
from secskill.reporting.html_report import HtmlReporter

REPORTER_REGISTRY: Dict[str, Type[BaseReporter]] = {
    "console": ConsoleReporter,
    "sarif": SarifReporter,
    "json": JsonReporter,
    "markdown": MarkdownReporter,
    "html": HtmlReporter,
}

def get_reporter(format_name: str) -> BaseReporter:
    """Retrieve an instantiated reporter for the given format identifier.
    
    Args:
        format_name: One of 'console', 'sarif', 'json', 'markdown', 'html'.
        
    Returns:
        Instantiated BaseReporter subclass.
        
    Raises:
        ValueError: If format_name is not supported.
    """
    fmt = format_name.lower().strip()
    reporter_cls = REPORTER_REGISTRY.get(fmt)
    if not reporter_cls:
        valid_formats = ", ".join(REPORTER_REGISTRY.keys())
        raise ValueError(f"Unknown format '{format_name}'. Supported formats: {valid_formats}")
    return reporter_cls()

__all__ = [
    "BaseReporter",
    "ConsoleReporter",
    "SarifReporter",
    "JsonReporter",
    "MarkdownReporter",
    "HtmlReporter",
    "REPORTER_REGISTRY",
    "get_reporter",
]
