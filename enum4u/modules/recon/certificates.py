from __future__ import annotations

import socket
import ssl
from urllib.parse import urlparse

from enum4u.core.context import ScanContext


def _hostname(target: str) -> str:
    value = str(target).strip()

    parsed = urlparse(
        value
        if "://" in value
        else f"//{value}",
    )

    return (
        parsed.hostname
        or value.split(":", 1)[0]
    )


def _port(target: str) -> int:
    value = str(target).strip()

    parsed = urlparse(
        value
        if "://" in value
        else f"//{value}",
    )

    if parsed.port:
        return parsed.port

    return 443


def run_certificate_recon(
    context: ScanContext,
) -> None:
    target = str(
        context.target
    ).strip()

    hostname = _hostname(target)
    port = _port(target)

    result = {
        "status": "skipped",
        "reason": None,
        "target": target,
        "hostname": hostname,
        "port": port,
        "certificate": None,
    }

    if not hostname:
        result["reason"] = (
            "hostname could not be determined"
        )

        context.metadata[
            "certificates"
        ] = result

        return

    if (
        port != 443
        and not target.lower().startswith(
            "https://"
        )
    ):
        result["reason"] = (
            "target does not indicate a TLS endpoint"
        )

        context.metadata[
            "certificates"
        ] = result

        return

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

        tls_context = (
            ssl.create_default_context()
        )

        with socket.create_connection(
            (hostname, port),
            timeout=timeout,
        ) as raw_socket:

            with tls_context.wrap_socket(
                raw_socket,
                server_hostname=hostname,
            ) as tls_socket:

                certificate = (
                    tls_socket.getpeercert()
                )

                cipher = (
                    tls_socket.cipher()
                )

                result[
                    "certificate"
                ] = {
                    "subject": certificate.get(
                        "subject"
                    ),
                    "issuer": certificate.get(
                        "issuer"
                    ),
                    "version": certificate.get(
                        "version"
                    ),
                    "serial_number": certificate.get(
                        "serialNumber"
                    ),
                    "not_before": certificate.get(
                        "notBefore"
                    ),
                    "not_after": certificate.get(
                        "notAfter"
                    ),
                    "subject_alt_name": certificate.get(
                        "subjectAltName"
                    ),
                    "cipher": (
                        cipher[0]
                        if cipher
                        else None
                    ),
                    "protocol": (
                        cipher[1]
                        if cipher
                        else None
                    ),
                }

                result[
                    "status"
                ] = "completed"

    except Exception as exc:
        result[
            "status"
        ] = "failed"

        result[
            "reason"
        ] = str(exc)

    context.metadata[
        "certificates"
    ] = result