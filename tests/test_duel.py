"""Tests for Autonomous AI Red Team vs. Blue Team Duel Arena (secskill duel)."""
from pathlib import Path
from typer.testing import CliRunner
from secskill.cli import app
from secskill.duel import (
    DuelArena,
    DuelValidator,
    RedTeamAgent,
    BlueTeamAgent,
    AttackPayload,
)

runner = CliRunner()


def test_validator_sqli_detection():
    vuln_code = (
        "def search(user_input):\n"
        "    query = f\"SELECT * FROM users WHERE name = '{user_input}'\"\n"
        "    cursor.execute(query)\n"
    )
    verdict = DuelValidator.validate(vuln_code, "sqli")
    assert not verdict.is_safe
    assert verdict.bypass_detected
    assert not verdict.ast_safe
    assert any("f-string" in v or "JoinedStr" in v for v in verdict.ast_violations)


def test_validator_sqli_hardened_parameterization():
    safe_code = (
        "def search(user_input):\n"
        "    query = \"SELECT * FROM users WHERE name = %s\"\n"
        "    cursor.execute(query, (user_input,))\n"
    )
    verdict = DuelValidator.validate(safe_code, "sqli")
    assert verdict.is_safe
    assert not verdict.bypass_detected
    assert verdict.ast_safe
    assert verdict.taint_clean


def test_validator_cmdi_detection_and_hardened():
    vuln_code = (
        "import os\n"
        "def ping(host):\n"
        "    os.system(f'ping -c 1 {host}')\n"
    )
    verdict_vuln = DuelValidator.validate(vuln_code, "cmdi")
    assert not verdict_vuln.is_safe
    assert any("os.system" in v for v in verdict_vuln.ast_violations)

    safe_code = (
        "import subprocess\n"
        "def ping(host):\n"
        "    subprocess.run(['ping', '-c', '1', host], shell=False)\n"
    )
    verdict_safe = DuelValidator.validate(safe_code, "cmdi")
    assert verdict_safe.is_safe
    assert verdict_safe.ast_safe


def test_validator_path_traversal():
    vuln_code = (
        "def load(name):\n"
        "    with open(f'/tmp/{name}', 'r') as f:\n"
        "        return f.read()\n"
    )
    verdict = DuelValidator.validate(vuln_code, "path-traversal")
    assert not verdict.is_safe

    safe_code = (
        "from pathlib import Path\n"
        "def load(name):\n"
        "    base = Path('/tmp').resolve()\n"
        "    target = (base / name).resolve()\n"
        "    if not target.is_relative_to(base):\n"
        "        raise PermissionError('Denied')\n"
        "    with open(target, 'r') as f:\n"
        "        return f.read()\n"
    )
    verdict_safe = DuelValidator.validate(safe_code, "path-traversal")
    assert verdict_safe.is_safe


def test_red_agent_payload_generation():
    agent = RedTeamAgent(provider_name="simulate")
    payload_r1 = agent.craft_exploit("code", "sqli", round_number=1)
    assert payload_r1.payload != ""
    assert "SQL" in payload_r1.vector

    payload_r2 = agent.craft_exploit("code", "sqli", round_number=2)
    assert "Comment" in payload_r2.name or "WAF" in payload_r2.bypass_technique


def test_blue_agent_patch_generation():
    agent = BlueTeamAgent(provider_name="simulate")
    dummy_payload = AttackPayload(
        name="SQLi",
        vector="CWE-89",
        payload="' OR 1=1 --",
        bypass_technique="Tautology",
        explanation="test",
    )
    patch = agent.create_patch("orig_code", "sqli", round_number=2, total_rounds=3, red_payload=dummy_payload)
    assert patch.code != ""
    assert "cursor.execute" in patch.code
    assert "%s" in patch.code or "?" in patch.code


def test_arena_full_run_sqli(tmp_path: Path):
    out_file = tmp_path / "hardened_sqli.py"
    arena = DuelArena(
        target="sqli",
        provider="simulate",
        max_rounds=3,
        turn_delay=0.0,
        output_path=out_file,
    )
    result = arena.run()
    assert result.winner == "BLUE"
    assert result.is_hardened
    assert out_file.is_file()
    saved_code = out_file.read_text(encoding="utf-8")
    assert "cursor.execute" in saved_code
    assert result.total_rounds >= 1


def test_arena_file_auto_apply(tmp_path: Path):
    target_file = tmp_path / "vulnerable_app.py"
    target_file.write_text(
        "import os\ndef ping(host):\n    os.system(f'ping {host}')\n",
        encoding="utf-8"
    )

    arena = DuelArena(
        target=str(target_file),
        provider="simulate",
        max_rounds=2,
        turn_delay=0.0,
        auto_apply=True,
    )
    result = arena.run()
    assert result.winner == "BLUE"
    assert result.is_hardened
    # Verify backup was created
    bak_file = tmp_path / "vulnerable_app.py.bak"
    assert bak_file.is_file()
    # Verify target file was replaced with hardened code
    hardened_content = target_file.read_text(encoding="utf-8")
    assert "subprocess.run" in hardened_content


def test_cli_duel_command_scenario():
    result = runner.invoke(app, ["duel", "sqli", "--rounds", "2", "--delay", "0"])
    assert result.exit_code == 0
    assert "DUEL ARENA" in result.stdout
    assert "RED TEAM" in result.stdout
    assert "BLUE TEAM" in result.stdout
    assert "BLUE TEAM TRIUMPHS" in result.stdout


def test_cli_duel_command_output_file(tmp_path: Path):
    out_file = tmp_path / "cli_hardened.py"
    result = runner.invoke(app, ["duel", "cmdi", "--rounds", "2", "--delay", "0", "-o", str(out_file)])
    assert result.exit_code == 0
    assert out_file.is_file()
    content = out_file.read_text(encoding="utf-8")
    assert "subprocess" in content

