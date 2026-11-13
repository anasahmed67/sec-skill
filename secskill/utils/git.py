"""Git helper functions."""
import subprocess
from pathlib import Path
from typing import Dict, Any

def get_git_info(repo_path: Path) -> Dict[str, Any]:
    try:
        branch = subprocess.check_output(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=repo_path, text=True, stderr=subprocess.DEVNULL
        ).strip()
        commit = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repo_path, text=True, stderr=subprocess.DEVNULL
        ).strip()
        diff_files = subprocess.check_output(
            ["git", "diff", "--name-only", "HEAD~1"], cwd=repo_path, text=True, stderr=subprocess.DEVNULL
        ).splitlines()
        return {"branch": branch, "commit": commit, "diff_files": diff_files}
    except Exception:
        return {"branch": "main", "commit": None, "diff_files": []}
