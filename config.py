"""
Configuration for the NoEyes secure terminal chat tool.

Supports loading from a config file (JSON) and centralizes constants.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

# Defaults
DEFAULT_PORT: int = 5000
BUFFER_SIZE: int = 4096
ENCODING: str = "utf-8"
DEFAULT_SERVER_HOST: str = "0.0.0.0"

# Cryptography
KDF_ITERATIONS: int = 390_000
KDF_SALT: bytes = b"noeyes-static-salt-v1"

# Rate limiting (messages per user per minute)
RATE_LIMIT_PER_MINUTE: int = 60

# Heartbeat (seconds)
HEARTBEAT_INTERVAL: float = 30.0
HEARTBEAT_TIMEOUT: float = 90.0

# Message history (last N messages sent to new joiners)
HISTORY_SIZE: int = 50

# Reconnect
RECONNECT_BASE_DELAY: float = 1.0
RECONNECT_MAX_DELAY: float = 60.0
RECONNECT_MAX_ATTEMPTS: int = 0  # 0 = infinite

# File transfer
FILE_CHUNK_SIZE: int = 65536
FILE_MAX_SIZE_MB: int = 50

# UI
COLORS_ENABLED: bool = True
DEFAULT_ROOM: str = "general"

# Config file locations (first found wins)
CONFIG_PATHS: tuple[str, ...] = (
    "noeyes_config.json",
    os.path.expanduser("~/.config/noeyes/config.json"),
    "/etc/noeyes/config.json",
)


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    """Load config from JSON file. Returns dict of overrides (empty if none)."""
    if path:
        p = Path(path)
        if p.is_file():
            try:
                with open(p, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                return {}
        return {}

    for loc in CONFIG_PATHS:
        p = Path(loc)
        if not p.is_absolute():
            p = Path.cwd() / p
        if p.is_file():
            try:
                with open(p, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                pass
    return {}


def get_config_value(config: dict[str, Any], key: str, default: Any) -> Any:
    """Get value from config dict with optional nested keys (e.g. 'server.port')."""
    keys = key.split(".")
    d = config
    for k in keys:
        if isinstance(d, dict) and k in d:
            d = d[k]
        else:
            return default
    return d
