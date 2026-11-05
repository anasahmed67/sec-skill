"""ScanContext builder aggregating repository metadata and files."""
from pathlib import Path
from typing import List, Optional
from secskill.models import ScanContext
from secskill.utils.git import get_git_info
from secskill.utils.files import discover_files, detect_languages

def build_scan_context(target_path: str, diff_only: bool = False) -> ScanContext:
    root = Path(target_path).resolve()
    files = discover_files(root)
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
