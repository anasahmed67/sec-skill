"""Unit and integration tests for AgentInstaller and secskill init --agent."""
from pathlib import Path
from typer.testing import CliRunner
from secskill.cli import app
from secskill.installer import AgentInstaller

runner = CliRunner()

def test_install_antigravity(tmp_path: Path):
    created = AgentInstaller.install_antigravity(tmp_path)
    assert len(created) >= 2
    assert (tmp_path / ".gemini" / "skills" / "secskill" / "SKILL.md").exists()
    assert (tmp_path / ".gemini" / "plugins" / "secskill" / "plugin.json").exists()

def test_install_claude(tmp_path: Path):
    created = AgentInstaller.install_claude(tmp_path)
    assert len(created) >= 3
    assert (tmp_path / ".claude" / "skills" / "secskill" / "SKILL.md").exists()
    assert (tmp_path / ".claude" / "rules.md").exists()
    assert (tmp_path / "CLAUDE.md").exists()

def test_install_cursor(tmp_path: Path):
    created = AgentInstaller.install_cursor(tmp_path)
    assert len(created) >= 3
    assert (tmp_path / ".cursor" / "rules" / "secskill.mdc").exists()
    assert (tmp_path / ".cursor" / "mcp.json").exists()
    assert (tmp_path / ".cursorrules").exists()

def test_install_codex(tmp_path: Path):
    created = AgentInstaller.install_codex(tmp_path)
    assert len(created) >= 2
    assert (tmp_path / ".mcp" / "secskill.json").exists()
    assert (tmp_path / "AGENTS.md").exists()

def test_install_all(tmp_path: Path):
    results = AgentInstaller.install_all(tmp_path)
    assert "antigravity" in results
    assert "claude" in results
    assert "cursor" in results
    assert "codex" in results
    assert "ci" in results
    assert (tmp_path / ".github" / "workflows" / "secskill.yml").exists()

def test_cli_init_omni_agent(tmp_path: Path):
    result = runner.invoke(app, ["init", "--target", str(tmp_path), "--agent", "all"])
    assert result.exit_code == 0
    assert "SecSkill Agent Integration Initialized Successfully!" in result.stdout
    assert (tmp_path / ".gemini" / "skills" / "secskill" / "SKILL.md").exists()
    assert (tmp_path / ".cursor" / "rules" / "secskill.mdc").exists()
    assert (tmp_path / ".claude" / "rules.md").exists()
    assert (tmp_path / ".mcp" / "secskill.json").exists()

