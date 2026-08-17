from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse


class TargetValidationError(ValueError):
    """Raised when a target is invalid."""


DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)

HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(?:\."
    r"(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))*$"
)


def _validate_port(port: int) -> int:
    if not 1 <= port <= 65535:
        raise TargetValidationError(
            f"Invalid port: {port}. Port must be between 1 and 65535."
        )

    return port


def normalize_target(target: str) -> str:
    target = target.strip()

    if not target:
        raise TargetValidationError("Target cannot be empty.")

    # URL input.
    if "://" in target:
        parsed = urlparse(target)

        if not parsed.hostname:
            raise TargetValidationError(
                f"Invalid URL target: {target}"
            )

        hostname = parsed.hostname.lower().rstrip(".")

        try:
            port = parsed.port
        except ValueError as exc:
            raise TargetValidationError(
                f"Invalid port in target: {target}"
            ) from exc

        if port is not None:
            _validate_port(port)
            return f"{hostname}:{port}"

        return hostname

    # Bare IPv6 address.
    try:
        ipaddress.IPv6Address(target)
        return target.lower()
    except ValueError:
        pass

    # host:port / IPv4:port.
    if ":" in target:
        # IPv6 with port must be written as [::1]:8000.
        if target.startswith("["):
            closing = target.find("]")

            if closing == -1:
                raise TargetValidationError(
                    f"Invalid IPv6 target: {target}"
                )

            hostname = target[1:closing]

            try:
                ipaddress.IPv6Address(hostname)
            except ValueError as exc:
                raise TargetValidationError(
                    f"Invalid IPv6 target: {target}"
                ) from exc

            remainder = target[closing + 1:]

            if not remainder.startswith(":"):
                raise TargetValidationError(
                    f"Invalid IPv6 target: {target}"
                )

            port_text = remainder[1:]

            if not port_text.isdigit():
                raise TargetValidationError(
                    f"Invalid port in target: {target}"
                )

            port = _validate_port(int(port_text))

            return f"[{hostname.lower()}]:{port}"

        # Normal hostname / IPv4 with port.
        hostname, port_text = target.rsplit(":", 1)

        if not hostname or not port_text.isdigit():
            raise TargetValidationError(
                f"Invalid target: {target}"
            )

        port = _validate_port(int(port_text))

        hostname = hostname.rstrip(".").lower()

        try:
            ipaddress.ip_address(hostname)
            return f"{hostname}:{port}"
        except ValueError:
            pass

        if not HOSTNAME_PATTERN.fullmatch(hostname):
            raise TargetValidationError(
                f"Invalid hostname: {hostname}"
            )

        return f"{hostname}:{port}"

    return target.rstrip(".").lower()


def validate_target(target: str) -> str:
    normalized = normalize_target(target)

    # Extract hostname from host:port for validation.
    hostname = normalized

    if normalized.startswith("["):
        hostname = normalized[1:].split("]", 1)[0]
    elif ":" in normalized:
        hostname = normalized.rsplit(":", 1)[0]

    # IP address.
    try:
        ipaddress.ip_address(hostname)
        return normalized
    except ValueError:
        pass

    # Domain / hostname.
    if DOMAIN_PATTERN.fullmatch(hostname):
        return normalized

    if HOSTNAME_PATTERN.fullmatch(hostname):
        return normalized

    raise TargetValidationError(
        f"Invalid domain, hostname, or IP address: {target}"
    )