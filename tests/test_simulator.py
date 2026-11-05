"""Tests for HackerSimulator and CLI simulate command."""
from typer.testing import CliRunner
from secskill.cli import app
from secskill.simulator import HackerSimulator

runner = CliRunner()

def test_list_and_get_scenarios():
    scenarios = HackerSimulator.list_scenarios()
    assert "sqli" in scenarios
    assert "cmdi" in scenarios
    assert "xss" in scenarios
    assert "path-traversal" in scenarios
    assert "ssrf" in scenarios
    assert "prompt-injection" in scenarios

    # Check alias resolution
    sqli_alias = HackerSimulator.get_scenario("cwe-89")
    assert sqli_alias is not None
    assert "SQL" in sqli_alias["title"]

    cmdi_alias = HackerSimulator.get_scenario("78")
    assert cmdi_alias is not None
    assert "Command" in cmdi_alias["title"]

def test_run_simulation():
    assert HackerSimulator.run_simulation("sqli") is True
    assert HackerSimulator.run_simulation("prompt-injection") is True
    assert HackerSimulator.run_simulation("non_existent_exploit") is False

def test_cli_simulate_command():
    # Test default sqli simulation
    result = runner.invoke(app, ["simulate", "sqli"])
    assert result.exit_code == 0
    assert "Hacker Simulator" in result.stdout
    assert "SQL Injection" in result.stdout
    assert "Attack Neutralized" in result.stdout

def test_cli_simulate_list():
    result = runner.invoke(app, ["simulate", "--list"])
    assert result.exit_code == 0
    assert "Available SecSkill Hacker Simulations" in result.stdout
    assert "sqli" in result.stdout
    assert "prompt-injection" in result.stdout

