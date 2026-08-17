from argparse import Namespace

from enum4u import cli


class FakeContext:
    target = "127.0.0.1:8000"

    metadata = {
        "status": "completed",
        "engine": {
            "timeout": 30,
            "concurrency": 4,
        },
        "tool_health": {
            "nmap": {
                "enabled": True,
                "available": True,
            },
        },
        "recon": {"count": 0},
        "dns": {"count": 0},
        "ports": {
            "count": 1,
            "status": "completed",
            "ports": [
                {
                    "port": 8000,
                    "protocol": "tcp",
                    "state": "closed",
                    "service": "http-alt",
                }
            ],
        },
        "http": {
            "count": 0,
            "status": "skipped",
        },
        "crawl": {
            "count": 1,
            "status": "completed",
            "urls": [
                "http://127.0.0.1:8000",
            ],
        },
        "nuclei": {
            "count": 0,
            "status": "completed",
        },
        "risk": {
            "count": 0,
            "status": "completed",
            "findings": [],
        },
        "graph": {
            "node_count": 3,
            "edge_count": 2,
            "status": "completed",
        },
        "pipeline": {
            "completed": [
                "target_validation",
            ],
            "failed": [],
            "skipped": [],
            "total_time": 0.1,
            "task_count": 1,
            "slowest_task": "target_validation",
            "slowest_time": 0.1,
            "fastest_task": "target_validation",
            "fastest_time": 0.1,
        },
    }


class FakeEngine:
    def __init__(self, target, mode, config):
        self.target = target
        self.mode = mode
        self.config = config

    def run(self):
        return FakeContext()


def test_build_parser_accepts_target():
    parser = cli.build_parser()

    args = parser.parse_args(
        ["127.0.0.1:8000"]
    )

    assert args.target == "127.0.0.1:8000"
    assert args.fast is False
    assert args.deep is False
    assert args.passive is False


def test_get_selected_mode_fast():
    args = Namespace(
        fast=True,
        deep=False,
        passive=False,
    )

    assert cli.get_selected_mode(args) == "fast"


def test_get_selected_mode_deep():
    args = Namespace(
        fast=False,
        deep=True,
        passive=False,
    )

    assert cli.get_selected_mode(args) == "deep"


def test_get_selected_mode_passive():
    args = Namespace(
        fast=False,
        deep=False,
        passive=True,
    )

    assert cli.get_selected_mode(args) == "passive"


def test_get_selected_mode_default():
    args = Namespace(
        fast=False,
        deep=False,
        passive=False,
    )

    assert cli.get_selected_mode(args) == "default"


def test_tool_health_status():
    assert cli._status(False, True) == "DISABLED"
    assert cli._status(True, True) == "READY"
    assert cli._status(True, False) == "MISSING"


def test_print_report_contains_core_sections(capsys):
    context = FakeContext()

    config = {
        "_meta": {
            "config_file": "configs/fast.yaml",
        }
    }

    cli.print_report(
        context=context,
        config=config,
        mode="fast",
        engine=None,
    )

    output = capsys.readouterr().out

    assert "ENUM4U" in output
    assert "Unified Security Assessment Framework" in output
    assert "127.0.0.1:8000" in output
    assert "FAST" in output
    assert "Tool Health:" in output
    assert "Recon:" in output
    assert "Open/Detected Ports:" in output
    assert "Risk Assessment:" in output
    assert "Attack Surface Graph:" in output
    assert "Pipeline Status:" in output
    assert "Performance:" in output


def test_main_fast_generates_reports(
    monkeypatch,
    capsys,
    tmp_path,
):
    context = FakeContext()

    config = {
        "_meta": {
            "config_file": "configs/fast.yaml",
        }
    }

    monkeypatch.setattr(
        cli,
        "load_config",
        lambda mode: config,
    )

    monkeypatch.setattr(
        cli,
        "Engine",
        FakeEngine,
    )

    monkeypatch.setattr(
        cli,
        "initialize_pipeline",
        lambda engine: None,
    )

    json_path = tmp_path / "enum4u-report.json"
    html_path = tmp_path / "enum4u-report.html"

    monkeypatch.setattr(
        cli,
        "generate_json_report",
        lambda context, output_dir: str(json_path),
    )

    monkeypatch.setattr(
        cli,
        "generate_html_report",
        lambda context, output_dir: str(html_path),
    )

    monkeypatch.setattr(
        "sys.argv",
        [
            "Enum4u",
            "127.0.0.1:8000",
            "--fast",
        ],
    )

    cli.main()

    output = capsys.readouterr().out

    assert "Mode   : FAST" in output
    assert "JSON Report :" in output
    assert "HTML Report :" in output


def test_main_without_target_prints_help(
    monkeypatch,
    capsys,
):
    monkeypatch.setattr(
        "sys.argv",
        ["Enum4u"],
    )

    cli.main()

    output = capsys.readouterr().out

    assert "usage:" in output
    assert "target" in output.lower()


def test_main_deep_selects_deep_mode(
    monkeypatch,
    capsys,
):
    context = FakeContext()

    config = {
        "_meta": {
            "config_file": "configs/deep.yaml",
        }
    }

    captured = {}

    def fake_load_config(mode):
        captured["mode"] = mode
        return config

    monkeypatch.setattr(
        cli,
        "load_config",
        fake_load_config,
    )

    monkeypatch.setattr(
        cli,
        "Engine",
        FakeEngine,
    )

    monkeypatch.setattr(
        cli,
        "initialize_pipeline",
        lambda engine: None,
    )

    monkeypatch.setattr(
        cli,
        "generate_json_report",
        lambda context, output_dir:
        "output/enum4u-report.json",
    )

    monkeypatch.setattr(
        cli,
        "generate_html_report",
        lambda context, output_dir:
        "output/enum4u-report.html",
    )

    monkeypatch.setattr(
        "sys.argv",
        [
            "Enum4u",
            "127.0.0.1:8000",
            "--deep",
        ],
    )

    cli.main()

    output = capsys.readouterr().out

    assert captured["mode"] == "deep"
    assert "Mode   : DEEP" in output