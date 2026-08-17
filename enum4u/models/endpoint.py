from dataclasses import dataclass


@dataclass(frozen=True)
class Endpoint:
    url: str
    status_code: int | None = None
    title: str | None = None
    technology: tuple[str, ...] = ()