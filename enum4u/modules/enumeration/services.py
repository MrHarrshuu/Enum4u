from __future__ import annotations

from enum4u.core.context import ScanContext


def run_service_enumeration(
    context: ScanContext,
) -> None:
    """
    Normalize service information already collected by
    the port-enumeration stage.

    This module does not launch a second port scan.
    """

    ports_metadata = context.metadata.get(
        "ports",
        {},
    )

    raw_ports = ports_metadata.get(
        "ports",
        [],
    )

    services = []

    for item in raw_ports:
        if not isinstance(item, dict):
            continue

        port = item.get("port")
        protocol = item.get(
            "protocol",
            "tcp",
        )

        service = str(
            item.get(
                "service",
                "",
            )
        ).strip()

        version = str(
            item.get(
                "version",
                "",
            )
        ).strip()

        state = str(
            item.get(
                "state",
                "",
            )
        ).strip().lower()

        services.append(
            {
                "port": port,
                "protocol": protocol,
                "service": service,
                "version": version,
                "state": state,
            }
        )

    open_services = [
        item
        for item in services
        if item.get("state") == "open"
    ]

    context.metadata[
        "services"
    ] = {
        "status": "completed",
        "count": len(services),
        "open_count": len(
            open_services
        ),
        "services": services,
    }