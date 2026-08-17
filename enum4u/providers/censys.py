from __future__ import annotations

import base64
import json
import os
import urllib.parse
import urllib.request

from enum4u.providers.base import (
    Provider,
    ProviderResult,
)


class CensysProvider(Provider):
    name = "censys"
    env_key = "CENSYS_API_ID"
    secret_key = "CENSYS_API_SECRET"

    def check_available(self) -> bool:
        return bool(
            os.getenv(self.env_key)
            and os.getenv(self.secret_key)
        )

    def query(
        self,
        target: str,
        timeout: int = 30,
    ) -> ProviderResult:

        api_id = os.getenv(
            self.env_key
        )

        api_secret = os.getenv(
            self.secret_key
        )

        if not api_id or not api_secret:
            return self.empty_result(
                "CENSYS_API_ID/CENSYS_API_SECRET "
                "are not configured"
            )

        encoded = urllib.parse.quote(
            target,
            safe="",
        )

        url = (
            "https://search.censys.io/api/v2/"
            f"hosts/{encoded}"
        )

        token = base64.b64encode(
            f"{api_id}:{api_secret}".encode()
        ).decode()

        try:
            request = urllib.request.Request(
                url,
                headers={
                    "Authorization":
                        f"Basic {token}",
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

            return ProviderResult(
                provider=self.name,
                status="completed",
                count=1,
                data=[parsed],
            )

        except Exception as exc:
            return ProviderResult(
                provider=self.name,
                status="failed",
                reason=str(exc),
            )