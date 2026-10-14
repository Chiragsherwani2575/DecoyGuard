"""Configuration handling for DecoyGuard.

Settings come from a JSON file (default ``decoyguard.json``) and can be
overridden with ``DG_<NAME>`` environment variables, e.g. ``DG_WEBHOOK_URL``.
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, fields
from typing import Optional

DEFAULT_CONFIG_PATH = "decoyguard.json"
ENV_PREFIX = "DG_"


@dataclass
class Config:
    # Public URL that decoys point at. Attackers must be able to reach it.
    base_url: str = "http://localhost:8080"
    host: str = "0.0.0.0"
    port: int = 8080
    db_path: str = "decoyguard.db"
    # Secret needed to view the dashboard / API.
    dashboard_key: str = ""
    # Slack/Teams/Discord-style incoming webhook (receives JSON with a "text" field).
    webhook_url: str = ""
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_from: str = ""
    smtp_to: str = ""
    # Only one notification per (decoy, source IP) inside this window.
    cooldown_seconds: int = 60
    # Trust X-Forwarded-For (only enable behind a reverse proxy you control).
    trust_proxy: bool = False

    def validate(self) -> None:
        self.base_url = self.base_url.rstrip("/")
        if not self.base_url.startswith(("http://", "https://")):
            raise ValueError("base_url must start with http:// or https://")
        if not (0 <= int(self.port) <= 65535):
            raise ValueError("port must be between 0 and 65535")
        if len(self.dashboard_key) < 16:
            raise ValueError(
                "dashboard_key must be at least 16 characters "
                "(run `decoyguard init` to generate one)"
            )
        if int(self.cooldown_seconds) < 0:
            raise ValueError("cooldown_seconds cannot be negative")


def _coerce(raw: str, current):
    if isinstance(current, bool):
        return raw.strip().lower() in ("1", "true", "yes", "on")
    if isinstance(current, int):
        return int(raw)
    return raw


def load_config(path: Optional[str] = None) -> Config:
    path = path or os.environ.get("DG_CONFIG", DEFAULT_CONFIG_PATH)
    data = {}
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    known = {f.name for f in fields(Config)}
    unknown = set(data) - known
    if unknown:
        raise ValueError("unknown config keys: " + ", ".join(sorted(unknown)))
    cfg = Config(**data)
    for name in known:
        raw = os.environ.get(ENV_PREFIX + name.upper())
        if raw is not None:
            setattr(cfg, name, _coerce(raw, getattr(cfg, name)))
    cfg.validate()
    return cfg


def save_config(cfg: Config, path: str) -> None:
    """Write the config readable by the owner only (it holds secrets)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(asdict(cfg), fh, indent=2)
        fh.write("\n")
