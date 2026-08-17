from __future__ import annotations

from urllib.parse import urlparse

from enum4u.core.context import ScanContext


def run_passive_recon(
    context: ScanContext,
) -> None:
    """
    Passive reconnaissance.

    This stage performs local normalization only.
    It does not actively probe the target.
    """

    target = str(
        context.target
    ).strip()

    parsed = urlparse(
        target
        if "://" in target
        else f"//{target}",
    )

    hostname = (
        parsed.hostname
        or target.split(
            ":",
            1,
        )[0]
    )

    assets = []

    if hostname:
        assets.append(
            {
                "type": "hostname",
                "value": hostname,
                "source": "passive",
            }
        )

    context.metadata[
        "passive_recon"
    ] = {
        "status": "completed",
        "mode": "passive",
        "target": target,
        "hostname": hostname,
        "sources": [],
        "assets": assets,
        "asset_count": len(
            assets
        ),
    }