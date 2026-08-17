from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ProviderResult:
    provider: str
    status: str
    count: int = 0
    data: list[dict[str, Any]] = field(
        default_factory=list
    )
    reason: str | None = None


class Provider(ABC):
    name: str = "unknown"
    env_key: str | None = None

    @abstractmethod
    def check_available(self) -> bool:
        """Return True when the provider is configured."""

    @abstractmethod
    def query(
        self,
        target: str,
        timeout: int = 30,
    ) -> ProviderResult:
        """Query the provider."""

    def empty_result(
        self,
        reason: str,
    ) -> ProviderResult:
        return ProviderResult(
            provider=self.name,
            status="skipped",
            reason=reason,
        )