from pathlib import Path
from typing import Any

import yaml


PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = PROJECT_ROOT / "configs"


class ConfigError(Exception):
    """Raised when Enum4u configuration cannot be loaded."""


def load_yaml(path: Path) -> dict[str, Any]:
    """Load a YAML configuration file."""

    if not path.exists():
        raise ConfigError(f"Configuration file not found: {path}")

    try:
        with path.open("r", encoding="utf-8") as file:
            data = yaml.safe_load(file)
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in {path}: {exc}") from exc

    if data is None:
        return {}

    if not isinstance(data, dict):
        raise ConfigError(f"Configuration root must be a mapping: {path}")

    return data


def get_config_path(mode: str) -> Path:
    """Return the configuration file for the selected mode."""

    allowed_modes = {
        "default": "default.yaml",
        "fast": "fast.yaml",
        "deep": "deep.yaml",
        "passive": "default.yaml",
    }

    if mode not in allowed_modes:
        raise ConfigError(f"Unsupported mode: {mode}")

    return CONFIG_DIR / allowed_modes[mode]


def load_config(mode: str = "default") -> dict[str, Any]:
    """Load Enum4u configuration for the selected mode."""

    config_path = get_config_path(mode)
    config = load_yaml(config_path)

    config["_meta"] = {
        "mode": mode,
        "config_file": str(config_path),
    }

    return config