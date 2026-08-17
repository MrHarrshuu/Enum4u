from enum4u.providers.base import (
    Provider,
    ProviderResult,
)

from enum4u.providers.registry import (
    ProviderRegistry,
)

from enum4u.providers.shodan import (
    ShodanProvider,
)

from enum4u.providers.virustotal import (
    VirusTotalProvider,
)

from enum4u.providers.censys import (
    CensysProvider,
)


def create_default_provider_registry() -> ProviderRegistry:
    registry = ProviderRegistry()

    registry.register(
        ShodanProvider()
    )

    registry.register(
        VirusTotalProvider()
    )

    registry.register(
        CensysProvider()
    )

    return registry


__all__ = [
    "Provider",
    "ProviderResult",
    "ProviderRegistry",
    "ShodanProvider",
    "VirusTotalProvider",
    "CensysProvider",
    "create_default_provider_registry",
]