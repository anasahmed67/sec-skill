"""Real-time file watcher and secret leak detector with desktop notifications."""
import os
import time
import math
import re
from pathlib import Path
from typing import List, Dict, Set, Tuple
from dataclasses import dataclass
from rich.console import Console
from rich.panel import Panel

from secskill.notifier import send_desktop_notification

console = Console()

IGNORE_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "vendor", "venv", ".venv", "env",
    "__pycache__", "dist", "build", ".pytest_cache", ".ruff_cache", ".mypy_cache",
    "target", "secskill", ".secskill", ".secskill_cache", "graphify-out", ".idea", ".vscode"
}

IGNORE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".pyc", ".exe", ".dll",
    ".so", ".zip", ".tar", ".gz", ".db", ".sqlite", ".bin", ".woff", ".woff2",
    ".ttf", ".eot", ".mp3", ".mp4", ".mov", ".pdf"
}

ALLOWLIST_WORDS = [
    "example", "sample", "dummy", "placeholder", "your_", "<", ">",
    "insert_", "fake", "replace_with", "xxxx", "000000", "123456",
    "abcdef", "my_secret", "changeme", "change_me", "test_key", "mock"
]

SECRET_RULES = [
    {
        "name": "AWS Access Key",
        "pattern": r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
        "min_entropy": 2.5
    },
    {
        "name": "AWS Secret Access Key",
        "pattern": r"(?i)(?:aws_secret_access_key|aws_secret_key)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?",
        "min_entropy": 3.8
    },
    {
        "name": "OpenAI / LLM API Key",
        "pattern": r"sk-(?:proj-)?[A-Za-z0-9_-]{32,}",
        "min_entropy": 3.2
    },
    {
        "name": "Anthropic API Key",
        "pattern": r"sk-ant-[A-Za-z0-9_-]{32,}",
        "min_entropy": 3.2
    },
    {
        "name": "GitHub Personal Access Token",
        "pattern": r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}",
        "min_entropy": 3.0
    },
    {
        "name": "Stripe Secret Key",
        "pattern": r"(?:sk_live|rk_live)_[0-9a-zA-Z]{24,34}",
        "min_entropy": 3.0
    },
    {
        "name": "Slack API Token / Webhook",
        "pattern": r"xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}|https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
        "min_entropy": 2.5
    },
    {
        "name": "Private Cryptographic Key",
        "pattern": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "min_entropy": 0.0
    },
    {
        "name": "Database Connection String with Credentials",
        "pattern": r"(?i)(?:postgres|postgresql|mysql|mongodb|redis)://[a-zA-Z0-9._%+-]+:([^@\s'\"]{4,})@[a-zA-Z0-9.-]+",
        "min_entropy": 2.5
    },
    {
        "name": "Generic High-Entropy Credential Assignment",
        "pattern": r"(?i)(?:api_key|apikey|secret_key|client_secret|auth_token|jwt_secret|private_key|db_password)\s*[:=]\s*['\"]([^'\"]{12,})['\"]",
        "min_entropy": 3.2
    }
]

def shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy for random string identification."""
    if not data:
        return 0.0
    freq: Dict[str, int] = {}
    for char in data:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def redact_secret(val: str) -> str:
    """Deterministically redact sensitive value to prefix and suffix."""
    val = val.strip("\"' ")
    if len(val) <= 8:
        return "****"
    return f"{val[:4]}...{val[-3:]}"

@dataclass
class SecretFinding:
    secret_type: str
    file_path: str
    line_number: int
    raw_snippet: str
    redacted_value: str

def scan_file_for_secrets(file_path: Path) -> List[SecretFinding]:
    """Scan a single file for exposed hardcoded secrets."""
    if not file_path.is_file():
        return []
    if file_path.suffix.lower() in IGNORE_EXTENSIONS:
        return []
    
    findings: List[SecretFinding] = []
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []

    lines = content.splitlines()
    for idx, line in enumerate(lines, 1):
        line_clean = line.strip()
        if not line_clean or line_clean.startswith("#") or line_clean.startswith("//"):
            # Check comments too if they look like credentials, but skip pure comment headers
            pass

        # Skip obvious documentation placeholders unless it's a real high-entropy key
        is_obvious_placeholder = any(w in line.lower() for w in ALLOWLIST_WORDS)

        for rule in SECRET_RULES:
            match = re.search(rule["pattern"], line)
            if not match:
                continue

            matched_text = match.group(1) if match.groups() else match.group(0)
            entropy = shannon_entropy(matched_text)

            if is_obvious_placeholder and entropy < 3.8:
                continue

            if entropy >= rule["min_entropy"]:
                redacted = redact_secret(matched_text)
                findings.append(
                    SecretFinding(
                        secret_type=rule["name"],
                        file_path=str(file_path),
                        line_number=idx,
                        raw_snippet=line_clean,
                        redacted_value=redacted,
                    )
                )
                break  # Don't duplicate matches on the same line

    return findings

class SecretWatcher:
    """File watcher that monitors changes and pops up desktop alerts on secret leaks."""

    def __init__(
        self,
        target_path: Path,
        enable_notify: bool = True,
        enable_sound: bool = True,
        interval: float = 0.5,
    ):
        self.target_path = Path(target_path).resolve()
        self.enable_notify = enable_notify
        self.enable_sound = enable_sound
        self.interval = interval
        self._file_mtimes: Dict[Path, int] = {}
        self._reported_leaks: Set[Tuple[str, int, str]] = set()

    def _should_ignore(self, path: Path) -> bool:
        """Check if path should be skipped."""
        parts = {p.lower() for p in path.parts}
        if any(ignored.lower() in parts for ignored in IGNORE_DIRS):
            return True
        name_lower = path.name.lower()
        if name_lower.startswith("secskill.") or name_lower.startswith(".secskill"):
            return True
        if name_lower in {"secskill", ".secskill", ".secskill_cache"}:
            return True
        if path.suffix.lower() in IGNORE_EXTENSIONS:
            return True
        return False

    def _discover_files(self) -> List[Path]:
        """Find all eligible files to monitor."""
        if self.target_path.is_file():
            return [self.target_path] if not self._should_ignore(self.target_path) else []

        valid_files = []
        try:
            for root, dirs, files in os.walk(self.target_path):
                # Prune ignored directories in-place
                dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
                for f in files:
                    fp = Path(root) / f
                    if not self._should_ignore(fp):
                        valid_files.append(fp)
        except Exception:
            pass
        return valid_files

    def check_once(self) -> List[SecretFinding]:
        """Check files for modifications and scan modified ones."""
        current_files = self._discover_files()
        new_or_modified: List[Path] = []

        for fp in current_files:
            try:
                mtime = fp.stat().st_mtime_ns
                prev_mtime = self._file_mtimes.get(fp)
                if prev_mtime is None or mtime > prev_mtime:
                    self._file_mtimes[fp] = mtime
                    # Only analyze if it was already known or first check
                    new_or_modified.append(fp)
            except Exception:
                continue

        all_findings: List[SecretFinding] = []
        for fp in new_or_modified:
            findings = scan_file_for_secrets(fp)
            for f in findings:
                leak_key = (f.file_path, f.line_number, f.secret_type)
                if leak_key not in self._reported_leaks:
                    self._reported_leaks.add(leak_key)
                    all_findings.append(f)

        return all_findings

    def handle_leak(self, finding: SecretFinding) -> None:
        """Trigger visual terminal alert and desktop popup."""
        rel_path = finding.file_path
        try:
            rel_path = str(Path(finding.file_path).relative_to(self.target_path))
        except Exception:
            pass

        title = "🚨 SecSkill Alert: Secret Leaked!"
        msg = f"Exposed {finding.secret_type} in {rel_path}:{finding.line_number}. Do NOT commit!"

        # 1. Desktop Notification + Sound
        if self.enable_notify:
            send_desktop_notification(title, msg, sound=self.enable_sound)

        # 2. Rich Terminal Warning Banner
        alert_body = (
            f"[bold red]WARNING: Hardcoded secret detected in real-time![/bold red]\n\n"
            f"• [bold]Type:[/bold] {finding.secret_type}\n"
            f"• [bold]File:[/bold] [cyan]{rel_path}:{finding.line_number}[/cyan]\n"
            f"• [bold]Value:[/bold] [yellow]{finding.redacted_value}[/yellow] [dim](redacted)[/dim]\n\n"
            f"[bold yellow]👉 Action Required:[/bold yellow] Remove or move this secret to a [green].env[/green] file immediately before git commit."
        )
        console.print(
            Panel(
                alert_body,
                title="[bold red]🚨 REAL-TIME SECRET LEAK INTERCEPTED[/bold red]",
                border_style="bright_red",
            )
        )

    def start(self) -> None:
        """Start the continuous watcher loop."""
        console.print(
            Panel(
                f"[bold green]🛡️ SecSkill Watchdog Active[/bold green]\n\n"
                f"• [bold]Watching Directory:[/bold] {self.target_path}\n"
                f"• [bold]Desktop Notifications:[/bold] {'[green]Enabled[/green]' if self.enable_notify else '[yellow]Disabled[/yellow]'}\n"
                f"• [bold]Audio Chime:[/bold] {'[green]Enabled[/green]' if self.enable_sound else '[yellow]Disabled[/yellow]'}\n\n"
                f"[dim]Listening for file saves... Press [bold]Ctrl+C[/bold] to exit.[/dim]",
                title="SecSkill Watch",
                border_style="cyan"
            )
        )

        # Initial baseline scan of existing files
        initial_findings = self.check_once()
        for finding in initial_findings:
            self.handle_leak(finding)

        try:
            while True:
                time.sleep(self.interval)
                new_findings = self.check_once()
                for finding in new_findings:
                    self.handle_leak(finding)
        except KeyboardInterrupt:
            console.print("\n[yellow]Watchdog stopped by user.[/yellow]")

