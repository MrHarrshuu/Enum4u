from __future__ import annotations

import re
import socket

from enum4u.core.context import ScanContext


def _extract_hostname(target: str) -> str:
    value = str(target).strip()

    value = re.sub(
        r"^https?://",
        "",
        value,
        flags=re.IGNORECASE,
    )

    value = value.split("/", 1)[0]
    value = value.split(":", 1)[0]

    return value.strip()


def _query_whois(
    hostname: str,
    timeout: float,
) -> str:
    """
    Minimal WHOIS client using the standard WHOIS
    TCP service.

    No third-party Python dependency required.
    """

    tld = hostname.rsplit(".", 1)[-1].lower()

    servers = {
        "com": "whois.verisign-grs.com",
        "net": "whois.verisign-grs.com",
        "org": "whois.pir.org",
        "info": "whois.afilias.net",
        "biz": "whois.biz",
        "io": "whois.nic.io",
        "dev": "whois.nic.google",
        "app": "whois.nic.google",
        "co": "whois.nic.co",
        "in": "whois.registry.in",
    }

    server = servers.get(
        tld,
        "whois.iana.org",
    )

    with socket.create_connection(
        (server, 43),
        timeout=timeout,
    ) as sock:

        sock.sendall(
            f"{hostname}\r\n".encode(
                "utf-8"
            )
        )

        chunks = []

        while True:
            data = sock.recv(4096)

            if not data:
                break

            chunks.append(data)

    return b"".join(
        chunks
    ).decode(
        "utf-8",
        errors="replace",
    )


def _parse_whois(
    raw: str,
) -> dict:
    fields = {}

    interesting = {
        "domain",
        "domain name",
        "registrar",
        "creation date",
        "created",
        "updated date",
        "updated",
        "expiry date",
        "expiration date",
        "name server",
        "status",
        "registrant organization",
    }

    for line in raw.splitlines():

        line = line.strip()

        if not line or ":" not in line:
            continue

        key, value = line.split(
            ":",
            1,
        )

        key = key.strip().lower()
        value = value.strip()

        if not value:
            continue

        if key not in interesting:
            continue

        normalized_key = (
            key.replace(
                " ",
                "_",
            )
        )

        existing = fields.get(
            normalized_key
        )

        if existing is None:
            fields[
                normalized_key
            ] = value

        elif isinstance(
            existing,
            list,
        ):
            existing.append(value)

        else:
            fields[
                normalized_key
            ] = [
                existing,
                value,
            ]

    return fields


def run_whois_recon(
    context: ScanContext,
) -> None:

    target = str(
        context.target
    ).strip()

    hostname = _extract_hostname(
        target
    )

    result = {
        "status": "skipped",
        "reason": None,
        "target": target,
        "hostname": hostname,
        "data": {},
    }

    if not hostname:
        result["reason"] = (
            "hostname could not be determined"
        )

        context.metadata[
            "whois"
        ] = result

        return

    # WHOIS is useful for domain names, not
    # localhost/IP targets.
    try:
        socket.inet_aton(hostname)

        result["reason"] = (
            "WHOIS domain lookup skipped for IP target"
        )

        context.metadata[
            "whois"
        ] = result

        return

    except OSError:
        pass

    try:
        timeout = float(
            context.config.get(
                "engine",
                {},
            ).get(
                "timeout",
                10,
            )
        )

        raw = _query_whois(
            hostname,
            timeout,
        )

        result["data"] = _parse_whois(
            raw
        )

        result["status"] = "completed"

    except Exception as exc:
        result["status"] = "failed"
        result["reason"] = str(exc)

    context.metadata[
        "whois"
    ] = result