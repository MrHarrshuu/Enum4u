from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _serialize(value: Any) -> Any:
    """
    Convert Enum4u runtime objects into JSON-safe values.
    """

    if value is None:
        return None

    if isinstance(value, (str, int, float, bool)):
        return value

    if isinstance(value, dict):
        return {
            str(key): _serialize(item)
            for key, item in value.items()
        }

    if isinstance(value, (list, tuple)):
        return [
            _serialize(item)
            for item in value
        ]

    if isinstance(value, set):
        return sorted(
            _serialize(item)
            for item in value
        )

    if hasattr(value, "__dict__"):
        return _serialize(
            vars(value)
        )

    return str(value)


def generate_json_report(
    context,
    output_dir: str = "output",
) -> str:

    output_path = Path(output_dir)

    output_path.mkdir(
        parents=True,
        exist_ok=True,
    )

    metadata = _serialize(
        context.metadata
    )

    assets = _serialize(
        getattr(
            context,
            "assets",
            [],
        )
    )

    subdomains = _serialize(
        getattr(
            context,
            "subdomains",
            set(),
        )
    )

    ips = _serialize(
        getattr(
            context,
            "ips",
            set(),
        )
    )

    endpoints = _serialize(
        getattr(
            context,
            "endpoints",
            [],
        )
    )

    report = {
        "enum4u": {
            "name": "Enum4u",
            "version": "0.1.0",
            "framework": (
                "Unified Security "
                "Assessment Framework"
            ),
        },

        "target": str(
            context.target
        ),

        "mode": str(
            getattr(
                context,
                "mode",
                "unknown",
            )
        ),

        "metadata": metadata,

        "assets": assets,

        "subdomains": subdomains,

        "ips": ips,

        "endpoints": endpoints,
    }

    report_file = (
        output_path /
        "enum4u-report.json"
    )

    report_file.write_text(
        json.dumps(
            report,
            indent=2,
            ensure_ascii=False,
            default=str,
        ),
        encoding="utf-8",
    )

    return str(report_file)