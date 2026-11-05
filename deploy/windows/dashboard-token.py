"""Copy the selected terminal project's token to the Windows clipboard without printing it.

Only needed to sign in from another device; on the same PC the dashboard opens without a token.
"""
import json
import os
from pathlib import Path
import subprocess
import sys

APP = Path.home() / ".local/share/watchtower/app"


def selected_token(root=APP):
    preferences = root / "files/terminal-ui/preferences.json"
    data = json.loads(preferences.read_text()) if preferences.exists() else {}
    token = Path(data.get("token_file") or "~/.config/watchtower/token").expanduser()
    if not token.is_absolute() or not token.is_file():
        raise ValueError("No saved login token. Open the terminal launcher and select your project first.")
    if token.stat().st_mode & 0o077 or token.stat().st_uid != os.getuid():
        raise ValueError("Token must be private and owned by your Ubuntu user (chmod 600).")
    value = token.read_text().strip()
    if not value.startswith("wt_") or any(c.isspace() for c in value):
        raise ValueError("The saved file does not contain a valid API token.")
    return value, str(data.get("project") or "local")


def main():
    try:
        token, project = selected_token()
        subprocess.run(["clip.exe"], input=token, text=True, check=True, capture_output=True, timeout=10)
        label = "".join(c for c in project if c.isalnum() or c in "-_.")
        print(f"Login token for {label} copied to clipboard. Paste it into the dashboard.")
        return 0
    except (ValueError, OSError, subprocess.SubprocessError):
        print("Could not copy the selected project token. Open the launcher, select your project, "
              "and check that its token file is private.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
