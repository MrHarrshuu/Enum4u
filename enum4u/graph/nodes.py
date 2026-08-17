from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class GraphNode:
    id: str
    node_type: str
    label: str
    metadata: dict = field(default_factory=dict)