"""Configuration loader for SecSkill."""
from pathlib import Path
from typing import Optional, List
import yaml
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    rules_dir: Optional[str] = None
    llm_provider: str = "ollama"  # openai, anthropic, ollama
    llm_model: Optional[str] = None
    llm_cache: bool = True
    llm_cache_dir: str = ".secskill_cache"
    fail_on_severity: str = "HIGH"
    ignored_paths: List[str] = [
        ".git",
        ".svn",
        ".hg",
        "node_modules",
        "vendor",
        "venv",
        ".venv",
        "env",
        "dist",
        "build",
        "target",
        "__pycache__",
        ".pytest_cache",
        ".ruff_cache",
        ".mypy_cache",
        ".idea",
        ".vscode",
        ".tox",
        "secskill",
        ".secskill",
        ".secskill_cache",
        "graphify-out",
    ]

    @classmethod
    def load(cls, config_path: Optional[Path] = None) -> "Settings":
        if config_path and config_path.exists():
            with open(config_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            return cls(**data)
        default_file = Path(".secskill.yaml")
        if default_file.exists():
            with open(default_file, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            return cls(**data)
        return cls()
