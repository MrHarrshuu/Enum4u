from pathlib import Path
import json

from enum4u.reporting.json import generate_json_report
from enum4u.reporting.html import generate_html_report


class FakeContext:
    target = "example.test"
    mode = "deep"

    metadata = {
        "status": "completed",

        "tool_health": {
            "nmap": {
                "enabled": True,
                "available": True,
            },
            "nuclei": {
                "enabled": True,
                "available": True,
            },
        },

        "recon": {
            "count": 1,
        },

        "dns": {
            "count": 1,
        },

        "ports": {
            "count": 1,
            "status": "completed",
            "ports": [
                {
                    "port": 443,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "https",
                    "version": "nginx 1.25",
                }
            ],
        },

        "http": {
            "count": 1,
            "status": "completed",
        },

        "crawl": {
            "count": 1,
            "urls": [
                "https://example.test/login",
            ],
            "status": "completed",
        },

        "endpoints": [
            "https://example.test/",
        ],

        "risk": {
            "status": "completed",
            "count": 1,
            "findings": [
                {
                    "id": "CVE-2026-TEST",
                    "name": "Test vulnerability",
                    "severity": "high",
                    "priority": "critical",
                    "confidence": "high",
                    "host": "example.test",
                }
            ],
        },

        "graph": {
            "status": "completed",
            "node_count": 3,
            "edge_count": 2,
        },

        "pipeline": {
            "completed": [
                "target_validation",
                "initialization",
            ],
            "failed": [],
            "skipped": [],
            "task_count": 2,
        },
    }

    assets = {
        "example.test",
    }

    subdomains = {
        "api.example.test",
    }

    ips = {
        "192.0.2.10",
    }

    endpoints = [
        "https://example.test/",
    ]


def test_json_report_created(tmp_path):
    context = FakeContext()

    result = generate_json_report(
        context,
        str(tmp_path),
    )

    report_file = Path(result)

    assert report_file.exists()
    assert report_file.name == "enum4u-report.json"


def test_json_report_structure(tmp_path):
    context = FakeContext()

    result = generate_json_report(
        context,
        str(tmp_path),
    )

    report = json.loads(
        Path(result).read_text(
            encoding="utf-8"
        )
    )

    assert "enum4u" in report
    assert "target" in report
    assert "mode" in report
    assert "metadata" in report
    assert "assets" in report
    assert "subdomains" in report
    assert "ips" in report
    assert "endpoints" in report


def test_json_report_preserves_target_and_mode(tmp_path):
    context = FakeContext()

    result = generate_json_report(
        context,
        str(tmp_path),
    )

    report = json.loads(
        Path(result).read_text(
            encoding="utf-8"
        )
    )

    assert report["target"] == "example.test"
    assert report["mode"] == "deep"


def test_json_report_preserves_metadata(tmp_path):
    context = FakeContext()

    result = generate_json_report(
        context,
        str(tmp_path),
    )

    report = json.loads(
        Path(result).read_text(
            encoding="utf-8"
        )
    )

    metadata = report["metadata"]

    assert metadata["status"] == "completed"
    assert metadata["risk"]["count"] == 1
    assert metadata["graph"]["node_count"] == 3


def test_json_report_serializes_sets(tmp_path):
    context = FakeContext()

    result = generate_json_report(
        context,
        str(tmp_path),
    )

    report = json.loads(
        Path(result).read_text(
            encoding="utf-8"
        )
    )

    assert isinstance(
        report["assets"],
        list,
    )

    assert isinstance(
        report["subdomains"],
        list,
    )

    assert isinstance(
        report["ips"],
        list,
    )


def test_html_report_created(tmp_path):
    context = FakeContext()

    result = generate_html_report(
        context,
        str(tmp_path),
    )

    report_file = Path(result)

    assert report_file.exists()
    assert report_file.name == "enum4u-report.html"


def test_html_report_contains_core_content(tmp_path):
    context = FakeContext()

    result = generate_html_report(
        context,
        str(tmp_path),
    )

    content = Path(result).read_text(
        encoding="utf-8"
    )

    assert "<!DOCTYPE html>" in content
    assert "ENUM4U" in content
    assert "example.test" in content
    assert "Unified Security Assessment Framework" in content


def test_html_report_contains_scan_data(tmp_path):
    context = FakeContext()

    result = generate_html_report(
        context,
        str(tmp_path),
    )

    content = Path(result).read_text(
        encoding="utf-8"
    )

    assert "443" in content
    assert "nginx 1.25" in content
    assert "https://example.test/" in content
    assert "https://example.test/login" in content


def test_html_report_contains_status_sections(tmp_path):
    context = FakeContext()

    result = generate_html_report(
        context,
        str(tmp_path),
    )

    content = Path(result).read_text(
        encoding="utf-8"
    )

    assert "Tool Health" in content
    assert "Detected Ports" in content
    assert "HTTP Endpoints" in content
    assert "Crawled URLs" in content