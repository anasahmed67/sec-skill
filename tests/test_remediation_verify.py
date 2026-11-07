"""Unit tests for SecSkillAgentSkill.verify_remediation and scan_url."""
from pathlib import Path
from secskill.agent_skill import SecSkillAgentSkill

def test_verify_remediation_success(tmp_path: Path):
    vuln_file = tmp_path / "app.py"
    vuln_file.write_text("eval(user_input)\n", encoding="utf-8")

    skill = SecSkillAgentSkill(target_dir=str(tmp_path))
    
    # Propose safe code replacement
    safe_patch = "import ast\nast.literal_eval(user_input)\n"
    res = skill.verify_remediation(str(vuln_file), proposed_patch=safe_patch)

    assert res["status"] == "PASS"
    assert res["remaining_count"] == 0
    assert res["resolved_count"] >= 1
    assert "neutralized" in res["message"].lower()

def test_verify_remediation_regression(tmp_path: Path):
    vuln_file = tmp_path / "app.py"
    vuln_file.write_text("eval(user_input)\n", encoding="utf-8")

    skill = SecSkillAgentSkill(target_dir=str(tmp_path))
    
    # Propose fix that replaces eval with command injection shell=True
    bad_patch = (
        "import subprocess\n"
        "subprocess.run('echo ' + user_input, shell=True)\n"
    )
    res = skill.verify_remediation(str(vuln_file), proposed_patch=bad_patch)

    assert res["status"] == "REGRESSION"
    assert res["regression_count"] >= 1
    assert "regression" in res["message"].lower()

def test_verify_remediation_persisting_failure(tmp_path: Path):
    vuln_file = tmp_path / "app.py"
    vuln_file.write_text("eval(user_input)\n", encoding="utf-8")

    skill = SecSkillAgentSkill(target_dir=str(tmp_path))
    
    # Propose patch that does not remove the eval
    unchanged_patch = "print('logging')\neval(user_input)\n"
    res = skill.verify_remediation(str(vuln_file), proposed_patch=unchanged_patch)

    assert res["status"] == "FAIL"
    assert res["remaining_count"] >= 1

