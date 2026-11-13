#!/usr/bin/env python3
"""
secskill/scripts/index_repo.py
Collect files, dependency manifests, routes, tests, auth middleware, and configs.
Builds an entry point and trust boundary map of the target codebase.
"""
import json
import argparse
from pathlib import Path
from typing import Dict, List, Any

IGNORE_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "venv", ".venv", "env",
    "__pycache__", ".pytest_cache", ".ruff_cache", "dist", "build",
    ".idea", ".vscode", "target", "vendor", ".tox",
    "secskill", ".secskill", ".secskill_cache", "graphify-out"
}

MANIFEST_FILENAMES = {
    "requirements.txt", "Pipfile", "Pipfile.lock", "pyproject.toml", "poetry.lock",
    "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
    "pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile",
    "go.mod", "go.sum", "Gemfile", "Gemfile.lock", "Cargo.toml", "Cargo.lock"
}

ROUTE_INDICATORS = [
    "@app.route", "@router.", "app.get(", "app.post(", "app.put(", "app.delete(",
    "router.get(", "router.post(", "path(", "re_path(", "@GetMapping",
    "@PostMapping", "@RequestMapping", "@RestController", "express.Router()"
]

AUTH_INDICATORS = [
    "login_required", "authenticate", "has_permission", "jwt.verify", "passport.authenticate",
    "SecurityFilterChain", "@PreAuthorize", "@RolesAllowed", "verify_token", "check_permission"
]

EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rs": "rust",
    ".rb": "ruby",
    ".php": "php",
    ".c": "c",
    ".cpp": "cpp",
    ".h": "c_header"
}

def is_ignored(path: Path, root: Path) -> bool:
    for part in path.relative_to(root).parts:
        if part.lower() in IGNORE_DIRS or part in IGNORE_DIRS or part.startswith(".git"):
            return True
    fname = path.name.lower()
    if fname.startswith("secskill.") or fname.startswith(".secskill"):
        return True
    return False

def index_repository(target_path: str) -> Dict[str, Any]:
    root = Path(target_path).resolve()
    if not root.exists():
        raise FileNotFoundError(f"Target path '{target_path}' does not exist.")

    manifests: List[str] = []
    source_files: Dict[str, List[str]] = {lang: [] for lang in set(EXTENSIONS.values())}
    routes: List[str] = []
    auth_middleware: List[str] = []
    configs: List[str] = []
    tests: List[str] = []
    all_files: List[str] = []

    if root.is_file():
        rel = root.name
        all_files.append(rel)
        ext = root.suffix.lower()
        if ext in EXTENSIONS:
            source_files[EXTENSIONS[ext]].append(rel)
        if root.name in MANIFEST_FILENAMES:
            manifests.append(rel)
    else:
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            if is_ignored(p, root):
                continue

            rel_str = str(p.relative_to(root)).replace("\\", "/")
            all_files.append(rel_str)
            name = p.name.lower()

            # Manifests
            if p.name in MANIFEST_FILENAMES:
                manifests.append(rel_str)

            # Tests
            if "test" in rel_str.lower() or name.startswith("test_") or name.endswith("_test.py") or ".spec." in name or ".test." in name:
                tests.append(rel_str)

            # Configs
            if name.startswith(".env") or name.endswith((".conf", ".config", ".yaml", ".yml", ".ini", ".properties")) or "config" in name:
                configs.append(rel_str)

            # Language sources
            ext = p.suffix.lower()
            if ext in EXTENSIONS:
                lang = EXTENSIONS[ext]
                source_files[lang].append(rel_str)

                # Route & Auth content inspection (sample first 200 lines)
                try:
                    with open(p, "r", encoding="utf-8", errors="ignore") as f:
                        content_sample = "".join([f.readline() for _ in range(200)])
                        if any(ri in content_sample for ri in ROUTE_INDICATORS):
                            routes.append(rel_str)
                        if any(ai in content_sample for ai in AUTH_INDICATORS):
                            auth_middleware.append(rel_str)
                except Exception:
                    pass

    # Prune empty languages
    active_sources = {k: v for k, v in source_files.items() if v}

    total_sources = sum(len(v) for v in active_sources.values())
    lang_percentages = {}
    if total_sources > 0:
        for k, v in active_sources.items():
            lang_percentages[k] = round((len(v) / total_sources) * 100, 1)

    return {
        "target": str(root),
        "total_files": len(all_files),
        "languages": lang_percentages,
        "manifests": manifests,
        "routes": routes,
        "auth_middleware": auth_middleware,
        "configs": configs,
        "tests": tests,
        "sources": active_sources,
        "trust_boundaries": {
            "entry_points": routes,
            "auth_barriers": auth_middleware,
            "manifest_count": len(manifests),
            "configuration_files": configs
        }
    }

def main():
    parser = argparse.ArgumentParser(description="SecSkill Repository Indexer")
    parser.add_argument("target", nargs="?", default=".", help="Target repository or directory path")
    parser.add_argument("-o", "--output", help="Optional output JSON file")
    args = parser.parse_args()

    result = index_repository(args.target)
    out_json = json.dumps(result, indent=2)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out_json)
        print(f"Index written to {args.output}")
    else:
        print(out_json)

if __name__ == "__main__":
    main()

