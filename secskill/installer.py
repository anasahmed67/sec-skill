"""
secskill/installer.py
Omni-Agent Installation Engine for Antigravity, Claude Code, Cursor, and Codex.
Enables SecSkill to be installed as an autonomous skill, MCP server, or rule set in any AI coding agent.
"""
from pathlib import Path
from typing import Dict, List

from secskill.templates import (
    SKILL_MD_CONTENT,
    SECSCAN_SKILL_CONTENT,
    SECPATCH_SKILL_CONTENT,
    AUDIT_PR_SKILL_CONTENT,
    SCAN_URL_SKILL_CONTENT,
    SECDUEL_SKILL_CONTENT,
    CURSOR_MDC_CONTENT,
    CLAUDE_RULES_CONTENT,
    ANTIGRAVITY_PLUGIN_JSON,
    CURSOR_MCP_JSON,
    GENERIC_MCP_CONFIG,
    GITHUB_WORKFLOW,
)

class AgentInstaller:
    """Installs SecSkill skills, MCP configurations, and rules for AI coding assistants."""

    @staticmethod
    def install_antigravity(target_dir: Path) -> List[str]:
        created = []
        antigravity_skills = {
            "secskill": SKILL_MD_CONTENT,
            "secscan": SECSCAN_SKILL_CONTENT,
            "secpatch": SECPATCH_SKILL_CONTENT,
            "audit-pr": AUDIT_PR_SKILL_CONTENT,
            "scan-url": SCAN_URL_SKILL_CONTENT,
            "secduel": SECDUEL_SKILL_CONTENT,
        }

        # Install both into .gemini/skills and standard Antigravity .agents/skills
        for base_folder in [target_dir / ".gemini" / "skills", target_dir / ".agents" / "skills"]:
            for skill_name, skill_content in antigravity_skills.items():
                sdir = base_folder / skill_name
                sdir.mkdir(parents=True, exist_ok=True)
                skill_file = sdir / "SKILL.md"
                skill_file.write_text(skill_content, encoding="utf-8")
                created.append(str(skill_file))

        plugins_dir = target_dir / ".gemini" / "plugins" / "secskill"
        plugins_dir.mkdir(parents=True, exist_ok=True)
        plugin_file = plugins_dir / "plugin.json"
        plugin_file.write_text(ANTIGRAVITY_PLUGIN_JSON, encoding="utf-8")
        created.append(str(plugin_file))
        return created

    @staticmethod
    def install_claude(target_dir: Path) -> List[str]:
        created = []
        claude_skills_dir = target_dir / ".claude" / "skills" / "secskill"
        claude_skills_dir.mkdir(parents=True, exist_ok=True)
        skill_file = claude_skills_dir / "SKILL.md"
        skill_file.write_text(SKILL_MD_CONTENT, encoding="utf-8")
        created.append(str(skill_file))

        rules_file = target_dir / ".claude" / "rules.md"
        rules_file.write_text(CLAUDE_RULES_CONTENT, encoding="utf-8")
        created.append(str(rules_file))

        claude_md = target_dir / "CLAUDE.md"
        if not claude_md.exists():
            claude_md.write_text(CLAUDE_RULES_CONTENT, encoding="utf-8")
            created.append(str(claude_md))
        return created

    @staticmethod
    def install_cursor(target_dir: Path) -> List[str]:
        created = []
        rules_dir = target_dir / ".cursor" / "rules"
        rules_dir.mkdir(parents=True, exist_ok=True)
        mdc_file = rules_dir / "secskill.mdc"
        mdc_file.write_text(CURSOR_MDC_CONTENT, encoding="utf-8")
        created.append(str(mdc_file))

        mcp_file = target_dir / ".cursor" / "mcp.json"
        mcp_file.write_text(CURSOR_MCP_JSON, encoding="utf-8")
        created.append(str(mcp_file))

        cursorrules = target_dir / ".cursorrules"
        cursorrules.write_text(CURSOR_MDC_CONTENT, encoding="utf-8")
        created.append(str(cursorrules))
        return created

    @staticmethod
    def install_codex(target_dir: Path) -> List[str]:
        created = []
        mcp_dir = target_dir / ".mcp"
        mcp_dir.mkdir(parents=True, exist_ok=True)
        mcp_file = mcp_dir / "secskill.json"
        mcp_file.write_text(GENERIC_MCP_CONFIG, encoding="utf-8")
        created.append(str(mcp_file))

        agent_md = target_dir / "AGENTS.md"
        if not agent_md.exists():
            agent_md.write_text(SKILL_MD_CONTENT, encoding="utf-8")
            created.append(str(agent_md))
        return created

    @staticmethod
    def install_ci(target_dir: Path) -> List[str]:
        created = []
        workflows_dir = target_dir / ".github" / "workflows"
        workflows_dir.mkdir(parents=True, exist_ok=True)
        workflow_file = workflows_dir / "secskill.yml"
        workflow_file.write_text(GITHUB_WORKFLOW, encoding="utf-8")
        created.append(str(workflow_file))
        return created

    @classmethod
    def install_all(cls, target_dir: Path) -> Dict[str, List[str]]:
        results = {
            "antigravity": cls.install_antigravity(target_dir),
            "claude": cls.install_claude(target_dir),
            "cursor": cls.install_cursor(target_dir),
            "codex": cls.install_codex(target_dir),
            "ci": cls.install_ci(target_dir),
        }
        return results

