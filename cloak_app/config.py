"""Config helpers."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv
import yaml

CONFIG_DIR = Path.home() / ".config" / "mad"
SECRETS_PATH = CONFIG_DIR / "secrets.env"
LAYERS_PATH = CONFIG_DIR / "identity_layers.yaml"
AUDIT_PATH = CONFIG_DIR / "cloak_last_audit.json"

DEFAULT_LAYERS = {
    "layers": {
        "personal": {"name": "Alexey", "email": "afischh@gmail.com", "platforms": ["github/afischh"]},
        "research": {"name": "ai_seam", "email": "<research-email>", "platforms": ["hackerone/ai_seam", "github/afischh"]},
        "mrph": {"name": "xen", "ip": "152.53.210.160", "tailscale": "100.127.175.23"},
    }
}


def ensure_files() -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if not SECRETS_PATH.exists():
        SECRETS_PATH.touch()
        os.chmod(SECRETS_PATH, 0o600)
    if not LAYERS_PATH.exists():
        LAYERS_PATH.write_text(yaml.safe_dump(DEFAULT_LAYERS, sort_keys=False), encoding="utf-8")
        os.chmod(LAYERS_PATH, 0o600)


def load_secrets() -> None:
    ensure_files()
    load_dotenv(SECRETS_PATH)


def load_layers() -> dict:
    ensure_files()
    return yaml.safe_load(LAYERS_PATH.read_text(encoding="utf-8")) or {"layers": {}}


def save_layers(data: dict) -> None:
    ensure_files()
    LAYERS_PATH.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
