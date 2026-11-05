"""File discovery and language detection helpers."""
from pathlib import Path
from typing import List, Set

IGNORED_DIRS = {".git", ".venv", "node_modules", "dist", "build", "__pycache__", ".secskill_cache"}

def discover_files(root: Path) -> List[Path]:
    if root.is_file():
        return [root]
    matched = []
    for p in root.rglob("*"):
        if p.is_file() and not any(part in IGNORED_DIRS for part in p.parts):
            matched.append(p)
    return matched

def detect_languages(files: List[Path]) -> List[str]:
    ext_map = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".java": "java",
        ".go": "go",
        ".rb": "ruby",
        ".php": "php",
    }
    langs: Set[str] = set()
    for f in files:
        if f.suffix in ext_map:
            langs.add(ext_map[f.suffix])
    return sorted(list(langs))
