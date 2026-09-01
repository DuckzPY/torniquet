"""Isolated identity profiles: separate SSH key + GPG keyring per profile."""
import json
import subprocess
from pathlib import Path

TORNIQUET_HOME = Path.home() / ".torniquet"
PROFILES_DIR = TORNIQUET_HOME / "profiles"
ACTIVE_FILE = TORNIQUET_HOME / "active_profile"


def create(name: str) -> dict:
    profile_dir = PROFILES_DIR / name
    if profile_dir.exists():
        raise FileExistsError(f"profile '{name}' already exists")

    ssh_dir = profile_dir / "ssh"
    gnupg_dir = profile_dir / "gnupg"
    ssh_dir.mkdir(parents=True)
    gnupg_dir.mkdir(mode=0o700)

    key_path = ssh_dir / "id_ed25519"
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-f", str(key_path), "-N", "", "-C", f"torniquet-{name}"],
        check=True,
        capture_output=True,
    )

    (profile_dir / "meta.json").write_text(json.dumps({"name": name}))
    return {"name": name, "ssh_key": str(key_path), "gnupg_home": str(gnupg_dir)}


def list_profiles() -> list[str]:
    if not PROFILES_DIR.exists():
        return []
    return sorted(p.name for p in PROFILES_DIR.iterdir() if p.is_dir())


def use(name: str) -> dict:
    profile_dir = PROFILES_DIR / name
    if not profile_dir.exists():
        raise FileNotFoundError(f"profile '{name}' does not exist")
    ACTIVE_FILE.write_text(name)
    return {
        "name": name,
        "GNUPGHOME": str(profile_dir / "gnupg"),
        "SSH_KEY": str(profile_dir / "ssh" / "id_ed25519"),
    }


def active() -> str | None:
    if not ACTIVE_FILE.exists():
        return None
    return ACTIVE_FILE.read_text().strip() or None
