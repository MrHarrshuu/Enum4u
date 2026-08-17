from __future__ import annotations

import os
import urllib.parse
import urllib.request

from enum4u.providers.base import (
    Provider,
    ProviderResult,
)


class ShodanProvider(Provider):
    name = "shodan"
    env_key = "SHODAN_API_KEY"

    def check_available(self) -> bool:
        return bool(
            os.getenv(self.env_key)
        )

    def query(
        self,
        target: str,
        timeout: int = 30,
    ) -> ProviderResult:

        api_key = os.getenv(
            self.env_key
        )

        if not api_key:
            return self.empty_result(
                "SHODAN_API_KEY is not configured"
            )

        query = urllib.parse.quote(
            target,
            safe="",
        )

        url = (
            "https://api.shodan.io/dns/resolve"
            f"?hostnames={query}"
            f"&key={urllib.parse.quote(api_key)}"
        )

        try:
            request = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "Enum4u/0.1"
                },
            )

            with urllib.request.urlopen(
                request,
                timeout=timeout,
            ) as response:
                raw = response.read().decode(
                    "utf-8"
                )

            import json

            parsed = json.loads(raw)

            data = []

            for hostname, ip in parsed.items():
                if ip:
                    data.append(
                        {
                            "hostname": hostname,
                            "ip": ip,
                        }
                    )

            return ProviderResult(
                provider=self.name,
                status="completed",
                count=len(data),
                data=data,
            )

        except Exception as exc:
            return ProviderResult(
                provider=self.name,
                status="failed",
                reason=str(exc),
            )