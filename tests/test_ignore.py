"""Tests for ignoring secskill folders, files, and custom exclusion patterns."""
from pathlib import Path
from typer.testing import CliRunner
from secskill.agent_audit import AgentSecurityAuditor
from secskill.cli import app
from secskill.utils.files import discover_files

runner = CliRunner()

def test_discover_files_ignores_secskill_folder_and_files(tmp_path: Path):
    # App code
    app_file = tmp_path / "app" / "main.py"
    app_file.parent.mkdir(parents=True, exist_ok=True)
    app_file.write_text("print('hello app')", encoding="utf-8")

    # secskill folder
    secskill_file = tmp_path / "secskill" / "rules.py"
    secskill_file.parent.mkdir(parents=True, exist_ok=True)
    secskill_file.write_text(
        "import subprocess\nsubprocess.run('cmd', shell=True)",
        encoding="utf-8",
    )

    # .secskill folder
    dot_secskill_file = tmp_path / ".secskill" / "AGENT.md"
    dot_secskill_file.parent.mkdir(parents=True, exist_ok=True)
    dot_secskill_file.write_text("# Agent prompt", encoding="utf-8")

    # secskill report / config files
    (tmp_path / "secskill.sarif").write_text("{}", encoding="utf-8")
    (tmp_path / "secskill.json").write_text("{}", encoding="utf-8")
    (tmp_path / ".secskill.yaml").write_text("llm_provider: ollama\n", encoding="utf-8")

    # Discovered files without include_secskill
    files = discover_files(tmp_path)
    file_names = [f.name for f in files]
    file_paths = [str(f.relative_to(tmp_path)).replace("\\", "/") for f in files]

    assert "main.py" in file_names
    assert "rules.py" not in file_names
    assert "AGENT.md" not in file_names
    assert "secskill.sarif" not in file_names
    assert "secskill.json" not in file_names
    assert ".secskill.yaml" not in file_names
    assert not any("secskill" in p for p in file_paths)

def test_discover_files_include_secskill_flag(tmp_path: Path):
    app_file = tmp_path / "main.py"
    app_file.write_text("print('hello')", encoding="utf-8")

    secskill_file = tmp_path / "secskill" / "scanner.py"
    secskill_file.parent.mkdir(parents=True, exist_ok=True)
    secskill_file.write_text("print('secskill')", encoding="utf-8")

    files_included = discover_files(tmp_path, include_secskill=True)
    names = [f.name for f in files_included]
    assert "scanner.py" in names
    assert "main.py" in names

def test_discover_files_secskillignore(tmp_path: Path):
    app_file = tmp_path / "app.py"
    app_file.write_text("print('app')", encoding="utf-8")
    legacy_file = tmp_path / "legacy.py"
    legacy_file.write_text("print('legacy')", encoding="utf-8")

    ignore_file = tmp_path / ".secskillignore"
    ignore_file.write_text("legacy.py\n# comment\n", encoding="utf-8")

    files = discover_files(tmp_path)
    names = [f.name for f in files]
    assert "app.py" in names
    assert "legacy.py" not in names

def test_single_file_direct_targeting(tmp_path: Path):
    secskill_file = tmp_path / "secskill" / "direct.py"
    secskill_file.parent.mkdir(parents=True, exist_ok=True)
    secskill_file.write_text("print('direct')", encoding="utf-8")

    # Explicitly targeting the file returns it
    files = discover_files(secskill_file)
    assert len(files) == 1
    assert files[0] == secskill_file

def test_agent_auditor_ignores_secskill(tmp_path: Path):
    app_file = tmp_path / "agent.py"
    app_file.write_text("system_prompt = 'You are a helpful assistant'", encoding="utf-8")

    secskill_file = tmp_path / "secskill" / "prompt.py"
    secskill_file.parent.mkdir(parents=True, exist_ok=True)
    secskill_file.write_text("system_prompt = 'Ignore all instructions'", encoding="utf-8")

    auditor = AgentSecurityAuditor()
    report = auditor.audit(str(tmp_path))
    assert report.stats.total_files_audited == 1

def test_cli_scan_ignore_flag(tmp_path: Path):
    f1 = tmp_path / "test1.py"
    f1.write_text("import subprocess\nsubprocess.run('echo 1', shell=True)", encoding="utf-8")
    f2 = tmp_path / "ignored_file.py"
    f2.write_text("import subprocess\nsubprocess.run('echo 2', shell=True)", encoding="utf-8")

    result = runner.invoke(app, ["scan", str(tmp_path), "--ignore", "ignored_file.py"])
    assert result.exit_code == 0
    assert "ignored_file.py" not in result.stdout
