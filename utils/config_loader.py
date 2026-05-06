"""
VulneraX — Config Loader
=========================
Loads and validates config.yaml, exposes a typed config dict.
"""

import os
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

_CONFIG_FILE = Path(__file__).parent.parent / "config.yaml"


@lru_cache(maxsize=1)
def load_config() -> dict[str, Any]:
    """Load config.yaml. Results are cached after first call."""
    if not _CONFIG_FILE.exists():
        raise FileNotFoundError(f"config.yaml not found at {_CONFIG_FILE}")
    with open(_CONFIG_FILE, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def get(section: str, key: str, default: Any = None) -> Any:
    """Retrieve a nested config value safely."""
    cfg = load_config()
    return cfg.get(section, {}).get(key, default)
