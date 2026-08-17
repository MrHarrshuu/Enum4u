from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class GraphEdge:
    source: str
    target: str
    relation: str
    metadata: dict = field(default_factory=dict)