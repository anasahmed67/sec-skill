"""Cross-platform desktop notifications and audio alerts for SecSkill."""
import os
import sys
import platform
import subprocess
import base64
from typing import Optional

def play_alert_sound() -> None:
    """Play an alert sound/chime according to the OS."""
    try:
        if platform.system() == "Windows":
            import winsound
            winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
        elif platform.system() == "Darwin":
            subprocess.run(["afplay", "/System/Library/Sounds/Sosumi.aiff"], capture_output=True)
        else:
            # Linux / Unix fallback terminal bell
            sys.stdout.write("\a")
            sys.stdout.flush()
    except Exception:
        sys.stdout.write("\a")
        sys.stdout.flush()

def send_desktop_notification(title: str, message: str, sound: bool = True) -> bool:
    """
    Send a native desktop notification on Windows, macOS, or Linux.
    Never throws an exception if the notification backend is unavailable.
    """
    if sound:
        play_alert_sound()

    system = platform.system()

    try:
        if system == "Windows":
            return _notify_windows(title, message)
        elif system == "Darwin":
            return _notify_macos(title, message)
        elif system == "Linux":
            return _notify_linux(title, message)
    except Exception:
        pass

    return False

def _notify_windows(title: str, message: str) -> bool:
    """Send a native Windows 10/11 Toast notification via PowerShell WinRT XML."""
    # Escape special XML chars in title and message
    clean_title = (
        title.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )
    clean_msg = (
        message.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )

    ps_script = f"""
[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
$xml = @"
<toast>
    <visual>
        <binding template="ToastGeneric">
            <text>{clean_title}</text>
            <text>{clean_msg}</text>
        </binding>
    </visual>
</toast>
"@
$doc = [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]::new()
$doc.LoadXml($xml)
$toast = [Windows.UI.Notifications.ToastNotification]::new($doc)
$notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("SecSkill Watchdog")
$notifier.Show($toast)
"""
    try:
        encoded = base64.b64encode(ps_script.encode("utf-16le")).decode("ascii")
        res = subprocess.run(
            ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
            capture_output=True,
            timeout=5,
        )
        return res.returncode == 0
    except Exception:
        return False

def _notify_macos(title: str, message: str) -> bool:
    """Send a native notification via macOS AppleScript."""
    clean_title = title.replace('"', '\\"')
    clean_msg = message.replace('"', '\\"')
    script = f'display notification "{clean_msg}" with title "{clean_title}" sound name "Sosumi"'
    res = subprocess.run(["osascript", "-e", script], capture_output=True, timeout=5)
    return res.returncode == 0

def _notify_linux(title: str, message: str) -> bool:
    """Send a notification via Linux notify-send."""
    res = subprocess.run(
        ["notify-send", title, message, "-u", "critical", "-a", "SecSkill"],
        capture_output=True,
        timeout=5,
    )
    return res.returncode == 0

