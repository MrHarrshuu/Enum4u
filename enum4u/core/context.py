from dataclasses import dataclass, field
from typing import Any


@dataclass
class ScanContext:
    target: str
    mode: str
    config: dict[str, Any]

    assets: set[str] = field(default_factory=set)
    subdomains: set[str] = field(default_factory=set)
    ips: set[str] = field(default_factory=set)
    urls: set[str] = field(default_factory=set)

    findings: list[dict[str, Any]] = field(default_factory=list)

    metadata: dict[str, Any] = field(default_factory=dict)

    def add_asset(self, asset: str) -> None:
        self.assets.add(asset)

    def add_subdomain(self, subdomain: str) -> None:
        self.subdomains.add(subdomain)

    def add_ip(self, ip: str) -> None:
        self.ips.add(ip)

    def add_url(self, url: str) -> None:
        self.urls.add(url)

    def add_finding(self, finding: dict[str, Any]) -> None:
        self.findings.append(finding)