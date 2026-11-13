from pathlib import Path
from typer.testing import CliRunner
from secskill.cli import app

runner = CliRunner()

def test_version_command():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "SecSkill version" in result.stdout

def test_explain_command():
    result = runner.invoke(app, ["explain", "--finding", "CWE-89"])
    assert result.exit_code == 0
    assert "SQL Injection" in result.stdout

def test_fix_dry_run():
    result = runner.invoke(app, ["fix", "--finding", "F-1001", "--dry-run"])
    assert result.exit_code == 0
    assert "Dry-run active" in result.stdout

def test_init_command(tmp_path: Path):
    result = runner.invoke(app, ["init", "--target", str(tmp_path)])
    assert result.exit_code == 0
    assert (tmp_path / ".secskill" / "AGENT.md").exists()
    assert (tmp_path / ".secskill" / "rules.md").exists()
    assert (tmp_path / ".secskill" / "policies.md").exists()
    assert (tmp_path / ".cursorrules").exists()
    assert (tmp_path / ".github" / "workflows" / "secskill.yml").exists()

def test_update_command(tmp_path: Path):
    result = runner.invoke(app, ["update", "--target", str(tmp_path), "--skills-only", "--no-global"])
    assert result.exit_code == 0
    assert "SecSkill Update Complete" in result.stdout
    assert (tmp_path / ".gemini" / "skills" / "secskill" / "SKILL.md").exists()
    assert (tmp_path / ".claude" / "skills" / "secskill" / "SKILL.md").exists()
    assert (tmp_path / ".cursor" / "rules" / "secskill.mdc").exists()

def test_upgrade_alias(tmp_path: Path):
    result = runner.invoke(app, ["upgrade", "--target", str(tmp_path), "--skills-only", "--no-global"])
    assert result.exit_code == 0
    assert "SecSkill Update Complete" in result.stdout
