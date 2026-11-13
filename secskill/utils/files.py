"""File discovery and language detection helpers."""
import fnmatch
from pathlib import Path
from typing import List, Set, Optional

IGNORED_DIRS: Set[str] = {
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
}

def is_secskill_file(path: Path) -> bool:
    """Check if file name corresponds to a secskill artifact, report, or configuration file."""
    name = path.name.lower()
    if name.startswith(".secskill"):
        return True
    if name.startswith("secskill.") or name == "secskill":
        return True
    known_secskill_files = {
        "secskill.sarif",
        "secskill.json",
        "secskill.yaml",
        ".secskill.yaml",
        "secskill.yml",
        "secskill.log",
        "report.html",
        "attack_map.html",
        "secskill_attack_graph.html",
    }
    if name in known_secskill_files:
        return True
    return False

def load_secskillignore(root: Path) -> List[str]:
    """Load exclusion glob patterns from .secskillignore if present."""
    patterns = []
    candidates = [root / ".secskillignore", root.parent / ".secskillignore"]
    for c in candidates:
        if c.is_file():
            try:
                for line in c.read_text(encoding="utf-8", errors="ignore").splitlines():
                    cleaned = line.strip()
                    if cleaned and not cleaned.startswith("#"):
                        patterns.append(cleaned)
            except Exception:
                pass
            break
    return patterns

def is_path_ignored(
    path: Path,
    root: Path,
    extra_dirs: Optional[Set[str]] = None,
    custom_patterns: Optional[List[str]] = None,
    include_secskill: bool = False,
) -> bool:
    """Determine whether a path should be skipped during file discovery."""
    try:
        rel = path.relative_to(root)
    except ValueError:
        rel = path

    fname = path.name.lower()

    # Check secskill files and directories if not explicitly included
    if not include_secskill:
        if is_secskill_file(path):
            return True
        for part in rel.parts[:-1]:
            if part.lower() in {"secskill", ".secskill", ".secskill_cache"}:
                return True

    # Check directory parts against ignored sets
    all_ignored = IGNORED_DIRS if extra_dirs is None else IGNORED_DIRS | extra_dirs
    if include_secskill:
        secskill_names = {"secskill", ".secskill", ".secskill_cache"}
        all_ignored = {d for d in all_ignored if d not in secskill_names}
    for part in rel.parts[:-1]:
        if part in all_ignored or part.lower() in all_ignored:
            return True
    if fname in all_ignored or fname.lower() in all_ignored:
        return True

    # Check against custom glob patterns and .secskillignore
    if custom_patterns:
        rel_posix = rel.as_posix().lower()
        fname = path.name.lower()
        for pat in custom_patterns:
            pat_lower = pat.lower().strip()
            if not pat_lower or pat_lower.startswith("#"):
                continue
            if fnmatch.fnmatch(rel_posix, pat_lower) or fnmatch.fnmatch(fname, pat_lower):
                return True
            if (
                fnmatch.fnmatch(rel_posix, f"*/{pat_lower}")
                or fnmatch.fnmatch(rel_posix, f"{pat_lower}/*")
            ):
                return True

    return False

def discover_files(
    root: Path,
    extra_ignores: Optional[List[str]] = None,
    include_secskill: bool = False,
) -> List[Path]:
    if root.is_file():
        return [root]

    # If the target directory itself is a secskill directory and secskill is excluded, return empty
    if not include_secskill:
        is_secskill_dir = root.name.lower() in {"secskill", ".secskill", ".secskill_cache"}
        if is_secskill_dir or is_secskill_file(root):
            return []

    custom_patterns = load_secskillignore(root)
    extra_dirs: Set[str] = set()
    if extra_ignores:
        for ign in extra_ignores:
            cleaned = ign.strip().lower()
            if not cleaned:
                continue
            custom_patterns.append(ign.strip())
            extra_dirs.add(cleaned)

    matched = []
    for p in root.rglob("*"):
        if p.is_file() and not is_path_ignored(
            p,
            root,
            extra_dirs=extra_dirs,
            custom_patterns=custom_patterns,
            include_secskill=include_secskill,
        ):
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
