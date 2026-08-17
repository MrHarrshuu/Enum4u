from enum4u.graph import build_attack_surface_graph


class FakeContext:
    target = "example.test"

    subdomains = {
        "api.example.test",
    }

    ips = {
        "192.0.2.10",
    }

    metadata = {
        "ports": {
            "ports": [
                {
                    "port": 443,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "https",
                    "version": "nginx 1.25",
                }
            ]
        },
        "endpoints": [
            "https://example.test/"
        ],
        "crawl": {
            "urls": [
                "https://example.test/login"
            ]
        },
        "risk": {
            "findings": [
                {
                    "name": "Test vulnerability",
                    "severity": "high",
                    "priority": "critical",
                    "confidence": "high",
                    "matched_at": "https://example.test/",
                }
            ]
        },
    }


def test_graph_contains_nodes_and_edges():
    graph = build_attack_surface_graph(
        FakeContext()
    )

    assert "nodes" in graph
    assert "edges" in graph

    assert len(graph["nodes"]) > 0
    assert len(graph["edges"]) > 0


def test_target_node_exists():
    graph = build_attack_surface_graph(
        FakeContext()
    )

    targets = [
        node
        for node in graph["nodes"]
        if node["type"] == "target"
    ]

    assert len(targets) == 1
    assert targets[0]["label"] == "example.test"


def test_subdomain_node_exists():
    graph = build_attack_surface_graph(
        FakeContext()
    )

    nodes = {
        node["label"]
        for node in graph["nodes"]
        if node["type"] == "subdomain"
    }

    assert "api.example.test" in nodes


def test_ip_node_exists():
    graph = build_attack_surface_graph(
        FakeContext()
    )

    nodes = {
        node["label"]
        for node in graph["nodes"]
        if node["type"] == "ip"
    }

    assert "192.0.2.10" in nodes


def test_port_node_exists():
    graph = build_attack_surface_graph(
        FakeContext()
    )

    ports = [
        node
        for node in graph["nodes"]
        if node["type"] == "port"
    ]

    assert len(ports) == 1
    assert ports[0]["label"] == "443/tcp"
    assert ports[0]["metadata"]["state"] == "open"


def test_http_and_url_nodes_exist():
    graph = build_attack_surface_graph(
        FakeContext()
    )

    types = {
        node["type"]
        for node in graph["nodes"]
    }

    assert "http" in types
    assert "url" in types


def test_finding_node_exists():
    graph = build_attack_surface_graph(
        FakeContext()
    )

    findings = [
        node
        for node in graph["nodes"]
        if node["type"] == "finding"
    ]

    assert len(findings) == 1
    assert findings[0]["label"] == "Test vulnerability"


def test_expected_relationships_exist():
    graph = build_attack_surface_graph(
        FakeContext()
    )

    relations = {
        edge["relation"]
        for edge in graph["edges"]
    }

    assert "contains" in relations
    assert "resolves_to" in relations
    assert "exposes" in relations
    assert "serves" in relations
    assert "discovered" in relations
    assert "has_finding" in relations


def test_graph_serialization_shape():
    graph = build_attack_surface_graph(
        FakeContext()
    )

    for node in graph["nodes"]:
        assert "id" in node
        assert "type" in node
        assert "label" in node
        assert "metadata" in node

    for edge in graph["edges"]:
        assert "source" in edge
        assert "target" in edge
        assert "relation" in edge
        assert "metadata" in edge