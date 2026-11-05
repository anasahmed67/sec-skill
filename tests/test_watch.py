"""Tests for real-time secret watcher and desktop notification engine."""
from pathlib import Path
from secskill.watcher import (
    shannon_entropy,
    redact_secret,
    scan_file_for_secrets,
    SecretWatcher,
)
from secskill.notifier import send_desktop_notification

def test_entropy_and_redaction():
    low_ent = shannon_entropy("aaaaaaaaaaaa")
    high_ent = shannon_entropy("xK9#mQ2$vL8!pZ1@")
    assert high_ent > low_ent

    redacted = redact_secret("AKIAIOSFODNN7EXAMPLE")
    assert redacted.startswith("AKIA")
    assert redacted.endswith("PLE")
    assert "..." in redacted

def test_scan_file_detects_openai_and_aws(tmp_path: Path):
    test_file = tmp_path / "config.py"
    test_file.write_text(
        'AWS_KEY = "AKIA1234567890ABCDEF"\n'
        'OPENAI_API_KEY = "sk-proj-abc123456789012345678901234567890"\n'
        'SAFE_LINE = "hello world"\n',
        encoding="utf-8"
    )

    findings = scan_file_for_secrets(test_file)
    assert len(findings) >= 2
    types = [f.secret_type for f in findings]
    assert any("AWS" in t for t in types)
    assert any("OpenAI" in t for t in types)

def test_secret_watcher_detects_new_and_modified_files(tmp_path: Path):
    watcher = SecretWatcher(target_path=tmp_path, enable_notify=False, enable_sound=False)
    
    # Initially no files
    assert watcher.check_once() == []

    # Create file with secret
    secret_file = tmp_path / "keys.py"
    secret_file.write_text('GITHUB_TOKEN = "ghp_1234567890abcdef1234567890abcdef123456"\n', encoding="utf-8")

    findings = watcher.check_once()
    assert len(findings) == 1
    assert "GitHub" in findings[0].secret_type

    # Second check without file change should not duplicate
    findings_again = watcher.check_once()
    assert len(findings_again) == 0

def test_desktop_notification_safe_execution():
    # Should execute safely without raising exceptions
    res = send_desktop_notification("Test Title", "Test Message", sound=False)
    assert isinstance(res, bool)

