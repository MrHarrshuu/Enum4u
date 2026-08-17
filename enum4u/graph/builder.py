from __future__ import annotations

from enum4u.graph.edges import GraphEdge
from enum4u.graph.nodes import GraphNode


class AttackSurfaceGraph:
    def __init__(self) -> None:
        self.nodes: dict[str, GraphNode] = {}
        self.edges: list[GraphEdge] = []

    def add_node(
        self,
        node_id: str,
        node_type: str,
        label: str,
        metadata: dict | None = None,
    ) -> None:
        if node_id in self.nodes:
            return

        self.nodes[node_id] = GraphNode(
            id=node_id,
            node_type=node_type,
            label=label,
            metadata=metadata or {},
        )

    def add_edge(
        self,
        source: str,
        target: str,
        relation: str,
        metadata: dict | None = None,
    ) -> None:
        edge = GraphEdge(
            source=source,
            target=target,
            relation=relation,
            metadata=metadata or {},
        )

        if edge not in self.edges:
            self.edges.append(edge)

    def to_dict(self) -> dict:
        return {
            "nodes": [
                {
                    "id": node.id,
                    "type": node.node_type,
                    "label": node.label,
                    "metadata": node.metadata,
                }
                for node in self.nodes.values()
            ],
            "edges": [
                {
                    "source": edge.source,
                    "target": edge.target,
                    "relation": edge.relation,
                    "metadata": edge.metadata,
                }
                for edge in self.edges
            ],
        }


def build_attack_surface_graph(
    context,
) -> dict:
    graph = AttackSurfaceGraph()

    target = str(context.target)

    target_id = f"target:{target}"

    graph.add_node(
        target_id,
        "target",
        target,
    )

    # =================================================
    # SUBDOMAINS
    # =================================================

    subdomains = sorted(
        getattr(
            context,
            "subdomains",
            set(),
        )
    )

    for subdomain in subdomains:

        subdomain = str(
            subdomain
        )

        node_id = (
            f"subdomain:{subdomain}"
        )

        graph.add_node(
            node_id,
            "subdomain",
            subdomain,
        )

        graph.add_edge(
            target_id,
            node_id,
            "contains",
        )

    # =================================================
    # IP ADDRESSES
    # =================================================

    ips = sorted(
        getattr(
            context,
            "ips",
            set(),
        )
    )

    for ip in ips:

        ip = str(ip)

        node_id = f"ip:{ip}"

        graph.add_node(
            node_id,
            "ip",
            ip,
        )

        graph.add_edge(
            target_id,
            node_id,
            "resolves_to",
        )

    # =================================================
    # PORTS / SERVICES
    # =================================================

    ports_data = context.metadata.get(
        "ports",
        {},
    )

    port_nodes = {}

    for port in ports_data.get(
        "ports",
        [],
    ):

        if not isinstance(
            port,
            dict,
        ):
            continue

        port_number = port.get(
            "port"
        )

        if port_number is None:
            continue

        protocol = port.get(
            "protocol",
            "tcp",
        )

        state = port.get(
            "state",
            "unknown",
        )

        service = port.get(
            "service",
            "",
        )

        version = port.get(
            "version",
            "",
        )

        node_id = (
            f"port:{port_number}/"
            f"{protocol}"
        )

        label = (
            f"{port_number}/"
            f"{protocol}"
        )

        graph.add_node(
            node_id,
            "port",
            label,
            {
                "state": state,
                "service": service,
                "version": version,
            },
        )

        graph.add_edge(
            target_id,
            node_id,
            "exposes",
        )

        port_nodes[
            (
                str(port_number),
                str(protocol),
            )
        ] = node_id

    # =================================================
    # HTTP ENDPOINTS
    # =================================================

    endpoints = context.metadata.get(
        "endpoints",
        [],
    )

    for endpoint in endpoints:

        if isinstance(
            endpoint,
            dict,
        ):
            value = (
                endpoint.get("url")
                or endpoint.get("endpoint")
            )
        else:
            value = endpoint

        if not value:
            continue

        value = str(value)

        node_id = (
            f"http:{value}"
        )

        graph.add_node(
            node_id,
            "http",
            value,
        )

        graph.add_edge(
            target_id,
            node_id,
            "serves",
        )

    # =================================================
    # CRAWLED URLS
    # =================================================

    crawl = context.metadata.get(
        "crawl",
        {},
    )

    for url in crawl.get(
        "urls",
        [],
    ):

        if not url:
            continue

        url = str(url)

        node_id = f"url:{url}"

        graph.add_node(
            node_id,
            "url",
            url,
        )

        graph.add_edge(
            target_id,
            node_id,
            "discovered",
        )

    # =================================================
    # TECHNOLOGIES
    # =================================================

    technology = context.metadata.get(
        "technology",
        {},
    )

    technologies = technology.get(
        "technologies",
        [],
    )

    technology_nodes = {}

    for item in technologies:

        if isinstance(
            item,
            dict,
        ):

            name = (
                item.get("name")
                or item.get("technology")
                or item.get("product")
            )

            metadata = dict(
                item
            )

        else:

            name = str(item)
            metadata = {}

        if not name:
            continue

        name = str(name)

        node_id = (
            f"technology:"
            f"{name.lower()}"
        )

        graph.add_node(
            node_id,
            "technology",
            name,
            metadata,
        )

        graph.add_edge(
            target_id,
            node_id,
            "uses",
        )

        technology_nodes[
            name.lower()
        ] = node_id

    # =================================================
    # SERVICE → TECHNOLOGY RELATIONSHIPS
    # =================================================

    service_data = context.metadata.get(
        "services",
        {},
    )

    enumerated_services = (
        service_data.get(
            "services",
            []
        )
    )

    if isinstance(
        enumerated_services,
        list,
    ):

        for item in enumerated_services:

            if not isinstance(
                item,
                dict,
            ):
                continue

            service_name = str(
                item.get(
                    "service",
                    "",
                )
            ).strip()

            if not service_name:
                continue

            technology_id = technology_nodes.get(
                service_name.lower()
            )

            if technology_id:

                for key, port_id in port_nodes.items():

                    if (
                        str(
                            graph.nodes[
                                port_id
                            ].metadata.get(
                                "service",
                                "",
                            )
                        ).lower()
                        == service_name.lower()
                    ):

                        graph.add_edge(
                            port_id,
                            technology_id,
                            "identified_as",
                        )

    # =================================================
    # VULNERABILITY INTELLIGENCE
    # =================================================

    enrichment = context.metadata.get(
        "enrichment",
        {},
    )

    enriched_services = enrichment.get(
        "services",
        [],
    )

    for service_index, service in enumerate(
        enriched_services
    ):

        if not isinstance(
            service,
            dict,
        ):
            continue

        port = service.get(
            "port"
        )

        protocol = service.get(
            "protocol",
            "tcp",
        )

        port_id = port_nodes.get(
            (
                str(port),
                str(protocol),
            )
        )

        for cve in service.get(
            "cves",
            [],
        ):

            if not isinstance(
                cve,
                dict,
            ):
                continue

            cve_id = str(
                cve.get(
                    "id",
                    "",
                )
            ).strip().upper()

            if not cve_id:
                continue

            cve_node_id = (
                f"cve:{cve_id}"
            )

            graph.add_node(
                cve_node_id,
                "cve",
                cve_id,
                {
                    "cvss": cve.get(
                        "cvss"
                    ),
                    "epss": cve.get(
                        "epss"
                    ),
                    "known_exploited": bool(
                        cve.get(
                            "known_exploited",
                            False,
                        )
                    ),
                    "intelligence_confidence": cve.get(
                        "intelligence_confidence"
                    ),
                    "description": cve.get(
                        "description",
                        "",
                    ),
                    "service": service.get(
                        "service"
                    ),
                    "version": service.get(
                        "version"
                    ),
                },
            )

            if port_id:

                graph.add_edge(
                    port_id,
                    cve_node_id,
                    "affected_by",
                )

            else:

                graph.add_edge(
                    target_id,
                    cve_node_id,
                    "affected_by",
                )

    # =================================================
    # RISK FINDINGS
    # =================================================

    risk = context.metadata.get(
        "risk",
        {},
    )

    for index, finding in enumerate(
        risk.get(
            "findings",
            [],
        )
    ):

        if not isinstance(
            finding,
            dict,
        ):
            continue

        finding_name = finding.get(
            "name",
            finding.get(
                "title",
                "Unknown finding",
            ),
        )

        finding_id = str(
            finding.get(
                "id",
                index,
            )
        )

        node_id = (
            f"finding:"
            f"{finding_id}:"
            f"{finding_name}"
        )

        graph.add_node(
            node_id,
            "finding",
            str(
                finding_name
            ),
            {
                "id": finding.get(
                    "id"
                ),
                "severity": finding.get(
                    "severity"
                ),
                "priority": finding.get(
                    "priority"
                ),
                "confidence": finding.get(
                    "confidence"
                ),
                "intelligence_confidence": finding.get(
                    "intelligence_confidence"
                ),
                "cvss": finding.get(
                    "cvss"
                ),
                "epss": finding.get(
                    "epss"
                ),
                "known_exploited": finding.get(
                    "known_exploited",
                    False,
                ),
                "matched_at": finding.get(
                    "matched_at"
                ),
                "host": finding.get(
                    "host"
                ),
                "port": finding.get(
                    "port"
                ),
            },
        )

        # Link CVE finding to CVE node
        finding_cve = str(
            finding.get(
                "id",
                "",
            )
        ).strip().upper()

        cve_node_id = (
            f"cve:{finding_cve}"
        )

        if finding_cve.startswith(
            "CVE-"
        ) and cve_node_id in graph.nodes:

            graph.add_edge(
                cve_node_id,
                node_id,
                "produces_finding",
            )

        else:

            graph.add_edge(
                target_id,
                node_id,
                "has_finding",
            )

    return graph.to_dict()