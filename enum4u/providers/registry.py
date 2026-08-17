from __future__ import annotations

from enum4u.providers.base import Provider


class ProviderRegistry:
    def __init__(self) -> None:
        self._providers: dict[str, Provider] = {}

    def register(
        self,
        provider: Provider,
    ) -> None:
        self._providers[
            provider.name
        ] = provider

    def get(
        self,
        name: str,
    ) -> Provider | None:
        return self._providers.get(name)

    def all(self) -> list[Provider]:
        return list(
            self._providers.values()
        )

    def names(self) -> list[str]:
        return sorted(
            self._providers.keys()
        )

    def health(self) -> dict[str, bool]:
        return {
            provider.name: provider.check_available()
            for provider in self.all()
        }