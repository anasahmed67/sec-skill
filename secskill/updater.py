"""
secskill/updater.py
One-Command Self-Updater & Omni-Agent Skill Synchronizer.
Enables developers and AI agents to update SecSkill, pull latest rules,
and synchronize agent skill manifests without re-downloading or manual setups.
"""
import sys
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional

from secskill.installer import AgentInstaller, SKILL_MD_CONTENT

class SecSkillUpdater:
    """Handles automated repository pulls, pip upgrades, and AI agent skill sync."""

    @staticmethod
    def is_git_repo(path: Path) -> bool:
        """Check if target path is inside a git repository."""
        return (path / ".git").is_dir() or (path.parent / ".git").is_dir()

    @classmethod
    def pull_git(cls, repo_dir: Path) -> Dict[str, Any]:
        """Pull latest changes from remote git repository if available."""
        if not shutil.which("git"):
            return {
                "success": False,
                "action": "git_pull",
                "message": "Git is not installed or not found in system PATH."
            }

        target = repo_dir if (repo_dir / ".git").is_dir() else repo_dir.parent
        if not (target / ".git").is_dir():
            return {
                "success": False,
                "action": "git_pull",
                "message": f"No .git directory found at {target}."
            }

        try:
            res = subprocess.run(
                ["git", "pull", "--ff-only"],
                cwd=str(target),
                capture_output=True,
                text=True,
                check=False
            )
            if res.returncode == 0:
                output = res.stdout.strip()
                return {
                    "success": True,
                    "action": "git_pull",
                    "message": output or "Repository updated successfully."
                }
            else:
                # If fast-forward fails, try standard pull
                res_fallback = subprocess.run(
                    ["git", "pull"],
                    cwd=str(target),
                    capture_output=True,
                    text=True,
                    check=False
                )
                return {
                    "success": res_fallback.returncode == 0,
                    "action": "git_pull",
                    "message": (res_fallback.stdout or res_fallback.stderr).strip()
                }
        except Exception as e:
            return {
                "success": False,
                "action": "git_pull",
                "message": f"Git pull error: {str(e)}"
            }

    @classmethod
    def upgrade_package(cls, repo_dir: Path) -> Dict[str, Any]:
        """Re-install or upgrade the secskill python package."""
        target = repo_dir if (repo_dir / "pyproject.toml").is_file() else repo_dir.parent
        python_exe = sys.executable

        try:
            if (target / "pyproject.toml").is_file():
                # In local source repository: perform editable install
                cmd = [python_exe, "-m", "pip", "install", "-e", str(target), "--no-deps"]
                desc = "Local editable package refreshed"
            else:
                # Remote / pip installed: upgrade from PyPI or git
                cmd = [python_exe, "-m", "pip", "install", "--upgrade", "secskill"]
                desc = "SecSkill package upgraded via pip"

            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False
            )
            return {
                "success": res.returncode == 0,
                "action": "pip_upgrade",
                "message": desc if res.returncode == 0 else res.stderr.strip() or res.stdout.strip()
            }
        except Exception as e:
            return {
                "success": False,
                "action": "pip_upgrade",
                "message": f"Package upgrade error: {str(e)}"
            }

    @classmethod
    def sync_agent_skills(
        cls, 
        target_dir: Path, 
        agent: str = "all", 
        sync_global: bool = True
    ) -> List[str]:
        """Synchronize updated SKILL.md, rules, and MCP configs to target and global agent directories."""
        updated_files = []
        agent_clean = agent.lower().strip()

        # 1. Sync project-level agent files
        if agent_clean == "all":
            results = AgentInstaller.install_all(target_dir)
            for files in results.values():
                updated_files.extend(files)
        elif agent_clean == "antigravity":
            updated_files.extend(AgentInstaller.install_antigravity(target_dir))
        elif agent_clean == "claude":
            updated_files.extend(AgentInstaller.install_claude(target_dir))
        elif agent_clean == "cursor":
            updated_files.extend(AgentInstaller.install_cursor(target_dir))
        elif agent_clean == "codex":
            updated_files.extend(AgentInstaller.install_codex(target_dir))

        # 2. Sync global user agent locations if requested
        if sync_global:
            home = Path.home()
            # Antigravity global skills
            global_gemini_skills = home / ".gemini" / "skills" / "secskill"
            global_gemini_config = home / ".gemini" / "config" / "skills" / "secskill"
            for gdir in [global_gemini_skills, global_gemini_config]:
                if gdir.parent.is_dir():
                    try:
                        gdir.mkdir(parents=True, exist_ok=True)
                        skill_f = gdir / "SKILL.md"
                        skill_f.write_text(SKILL_MD_CONTENT, encoding="utf-8")
                        updated_files.append(str(skill_f))
                    except Exception:
                        pass

            # Claude global skills
            global_claude_skills = home / ".claude" / "skills" / "secskill"
            if global_claude_skills.parent.is_dir():
                try:
                    global_claude_skills.mkdir(parents=True, exist_ok=True)
                    claude_f = global_claude_skills / "SKILL.md"
                    claude_f.write_text(SKILL_MD_CONTENT, encoding="utf-8")
                    updated_files.append(str(claude_f))
                except Exception:
                    pass

        return updated_files

    @classmethod
    def run_update(
        cls,
        target_dir: Path,
        agent: str = "all",
        skip_git: bool = False,
        skip_pip: bool = False,
        skills_only: bool = False,
        sync_global: bool = True
    ) -> Dict[str, Any]:
        """Execute complete update routine."""
        results: Dict[str, Any] = {
            "git": None,
            "pip": None,
            "skills_synced": []
        }

        # Step 1: Git Pull
        if not skills_only and not skip_git:
            results["git"] = cls.pull_git(target_dir)

        # Step 2: Pip Upgrade
        if not skills_only and not skip_pip:
            results["pip"] = cls.upgrade_package(target_dir)

        # Step 3: Sync Agent Skills & Rules
        results["skills_synced"] = cls.sync_agent_skills(
            target_dir=target_dir,
            agent=agent,
            sync_global=sync_global
        )

        return results
