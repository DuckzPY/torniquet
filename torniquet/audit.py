"""Scan the local machine for common opsec mistakes. No network calls."""
import os
import re
import stat
from pathlib import Path

KEY_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),          # AWS access key
    re.compile(r"-----BEGIN (RSA|OPENSSH|DSA|EC) PRIVATE KEY-----"),
    re.compile(r"ghp_[A-Za-z0-9]{36}"),        # GitHub token
]

SENSITIVE_FILES = [
    Path.home() / ".aws" / "credentials",
    Path.home() / ".ssh" / "id_rsa",
    Path.home() / ".ssh" / "id_ed25519",
]

CLOUD_SYNC_DIRS = ["Dropbox", "OneDrive", "Google Drive", "iCloudDrive"]


def _check_shell_history() -> dict:
    hist_files = [Path.home() / ".bash_history", Path.home() / ".zsh_history"]
    hits = 0
    for hist in hist_files:
        if not hist.exists():
            continue
        try:
            text = hist.read_text(errors="ignore")
        except OSError:
            continue
        for pattern in KEY_PATTERNS:
            hits += len(pattern.findall(text))
    return {
        "name": "shell history",
        "ok": hits == 0,
        "detail": "clear" if hits == 0 else f"{hits} possible key pattern(s) found",
    }


def _check_file_permissions(fix: bool = False) -> dict:
    issues = []
    for f in SENSITIVE_FILES:
        if not f.exists():
            continue
        mode = stat.S_IMODE(f.stat().st_mode)
        if mode & 0o077:  # readable/writable by group or others
            if fix:
                os.chmod(f, 0o600)
                issues.append(f"{f.name} was {oct(mode)}, fixed to 0600")
            else:
                issues.append(f"{f.name} permissions too open ({oct(mode)})")
    return {
        "name": "sensitive file permissions",
        "ok": len(issues) == 0,
        "detail": "clear" if not issues else "; ".join(issues),
    }


def _check_cloud_sync() -> dict:
    found = [d for d in CLOUD_SYNC_DIRS if (Path.home() / d).exists()]
    return {
        "name": "cloud sync folders",
        "ok": len(found) == 0,
        "detail": "clear" if not found else f"found: {', '.join(found)}",
    }


def _check_ssh_agent_forwarding() -> dict:
    ssh_config = Path.home() / ".ssh" / "config"
    risky = False
    if ssh_config.exists():
        text = ssh_config.read_text(errors="ignore")
        if re.search(r"^\s*ForwardAgent\s+yes", text, re.MULTILINE | re.IGNORECASE):
            risky = True
    return {
        "name": "ssh agent forwarding",
        "ok": not risky,
        "detail": "clear" if not risky else "ForwardAgent yes set globally in ssh config",
    }


def run_audit(fix: bool = False) -> list[dict]:
    return [
        _check_shell_history(),
        _check_file_permissions(fix=fix),
        _check_cloud_sync(),
        _check_ssh_agent_forwarding(),
    ]
