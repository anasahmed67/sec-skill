"""ScanContext builder aggregating repository metadata and files."""
from pathlib import Path
from typing import List, Optional
from secskill.models import ScanContext
from secskill.utils.git import get_git_info
from secskill.config import Settings
from secskill.utils.files import discover_files, detect_languages

def build_scan_context(
    target_path: str,
    diff_only: bool = False,
    extra_ignores: Optional[List[str]] = None,
    include_secskill: bool = False,
) -> ScanContext:
    root = Path(target_path).resolve()

    # Load configuration if present
    cfg_file = root / ".secskill.yaml" if root.is_dir() else root.parent / ".secskill.yaml"
    settings = Settings.load(cfg_file if cfg_file.exists() else None)

    all_ignores = list(extra_ignores or [])
    if settings.ignored_paths:
        for p in settings.ignored_paths:
            if p not in all_ignores:
                all_ignores.append(p)

    files = discover_files(root, extra_ignores=all_ignores, include_secskill=include_secskill)
    languages = detect_languages(files)
    git_info = get_git_info(root.parent if root.is_file() else root)
    
    base = root.parent if root.is_file() else root
    rel_files = [str(f.relative_to(base)).replace("\\", "/") for f in files]

    return ScanContext(
        target_path=str(root),
        files=rel_files,
        languages=languages,
        git_branch=git_info.get("branch"),
        git_commit=git_info.get("commit"),
        git_diff_files=git_info.get("diff_files", []) if diff_only else [],
    )
