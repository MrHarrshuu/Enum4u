from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request

from enum4u.providers.base import (
    Provider,
    ProviderResult,
)


class VirusTotalProvider(Provider):
    name = "virustotal"
    env_key = "VIRUSTOTAL_API_KEY"

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
                "VIRUSTOTAL_API_KEY is not configured"
            )

        encoded = urllib.parse.quote(
            target,
            safe="",
        )

        url = (
            "https://www.virustotal.com/api/v3/domains/"
            f"{encoded}"
        )

        try:
            request = urllib.request.Request(
                url,
                headers={
                    "x-apikey": api_key,
                    "User-Agent": "Enum4u/0.1",
                },
            )

            with urllib.request.urlopen(
                request,
                timeout=timeout,
            ) as response:
                raw = response.read().decode(
                    "utf-8"
                )

            parsed = json.loads(raw)

            attributes = (
                parsed
                .get("data", {})
                .get("attributes", {})
            )

            result = {
                "target": target,
                "reputation": attributes.get(
                    "reputation"
                ),
                "last_analysis_stats": attributes.get(
                    "last_analysis_stats",
                    {},
                ),
            }

            return ProviderResult(
                provider=self.name,
                status="completed",
                count=1,
                data=[result],
            )

        except Exception as exc:
            return ProviderResult(
                provider=self.name,
                status="failed",
                reason=str(exc),
            )