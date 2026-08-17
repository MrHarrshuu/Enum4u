from __future__ import annotations

import argparse

from enum4u.config import ConfigError, load_config
from enum4u.core.engine import Engine
from enum4u.core.orchestrator import initialize_pipeline
from enum4u.reporting.html import generate_html_report
from enum4u.reporting.json import generate_json_report
from enum4u.utils.validation import TargetValidationError


VERSION = "0.1.0"


MODULE_FLAGS = {
    "recon": "recon",
    "dns": "dns",
    "subdomains": "subdomains",
    "certificates": "certificates",
    "whois": "whois",
    "ports": "ports",
    "services": "services",
    "technology": "technology",
    "tls": "tls",
    "web": "web",
    "crawl": "crawl",
    "nuclei": "nuclei",
    "risk": "risk",
    "graph": "graph",
}


TOOL_MAP = {
    "dns": {"dnsx"},
    "subdomains": {"subfinder"},
    "certificates": {"dnsx"},
    "whois": set(),
    "ports": {"nmap"},
    "services": {"nmap"},
    "technology": {"httpx"},
    "tls": {"nmap"},
    "web": {"httpx"},
    "crawl": {"katana"},
    "nuclei": {"nuclei"},
}


def _status(
    enabled: bool,
    available: bool,
) -> str:

    if not enabled:
        return "DISABLED"

    if available:
        return "READY"

    return "MISSING"


def print_banner() -> None:

    print(
        r"""
       .       .
       |       |
      ||       ||
     \\(       )//
       | [---] |
     .-=\ ___ /=-.
    /   \_____/   \
   / \    |    / \
  /___\   |   /___\
      \   |   /
       \__|__/
      /  / \  \
     /__/   \__\

              E N U M 4 U
       SECURITY ASSESSMENT FRAMEWORK
"""
    )


def print_index() -> None:

    print_banner()

    print(
        """
  ┌─ MODES ────────────────────────────────────────────────┐
  │                                                       │
  │  --fast       Quick security assessment               │
  │  --deep       Full enumeration + intelligence         │
  │  --active     Active enumeration                      │
  │  --passive    Passive reconnaissance                  │
  │                                                       │
  └───────────────────────────────────────────────────────┘
"""
    )

    print(
        """
  ┌─ RECON ────────────────────────────────────────────────┐
  │                                                       │
  │  --recon         Complete reconnaissance              │
  │  --dns           DNS enumeration                      │
  │  --subdomains    Subdomain enumeration               │
  │  --certificates  Certificate reconnaissance           │
  │  --whois         WHOIS reconnaissance                 │
  │                                                       │
  └───────────────────────────────────────────────────────┘
"""
    )

    print(
        """
  ┌─ ENUMERATION ──────────────────────────────────────────┐
  │                                                       │
  │  --ports         Port enumeration                     │
  │  --services      Service enumeration                  │
  │  --technology    Technology detection                 │
  │  --tls           TLS enumeration                      │
  │                                                       │
  └───────────────────────────────────────────────────────┘
"""
    )

    print(
        """
  ┌─ WEB ──────────────────────────────────────────────────┐
  │                                                       │
  │  --web           HTTP enumeration + crawling          │
  │  --crawl         Web crawling                         │
  │                                                       │
  └───────────────────────────────────────────────────────┘
"""
    )

    print(
        """
  ┌─ ASSESSMENT ───────────────────────────────────────────┐
  │                                                       │
  │  --nuclei        Vulnerability assessment             │
  │  --risk          Risk analysis                        │
  │  --graph         Attack surface graph                │
  │                                                       │
  └───────────────────────────────────────────────────────┘
"""
    )

    print(
        """
  ┌─ QUICK START ──────────────────────────────────────────┐
  │                                                       │
  │  Enum4u example.com --recon                           │
  │  Enum4u example.com --dns                             │
  │  Enum4u example.com --deep                            │
  │  Enum4u 10.10.10.10 --ports                           │
  │                                                       │
  └───────────────────────────────────────────────────────┘

  ⚠  Authorized security testing only.

     Enum4u // Security starts with visibility
"""
    )


def build_parser() -> argparse.ArgumentParser:

    parser = argparse.ArgumentParser(
        prog="Enum4u",
        description=(
            "Enum4u - Unified Security Assessment Framework"
        ),
    )

    parser.add_argument(
        "target",
        nargs="?",
        help=(
            "Authorized target domain, hostname, "
            "IP, or host:port"
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"Enum4u v{VERSION}",
    )

    mode_group = parser.add_mutually_exclusive_group()

    mode_group.add_argument(
        "--fast",
        action="store_true",
        help="Run fast assessment mode",
    )

    mode_group.add_argument(
        "--deep",
        action="store_true",
        help="Run deep assessment mode",
    )

    mode_group.add_argument(
        "--active",
        action="store_true",
        help="Run active enumeration mode",
    )

    mode_group.add_argument(
        "--passive",
        action="store_true",
        help="Run passive reconnaissance mode",
    )

    module_group = parser.add_argument_group(
        "module selection"
    )

    for flag, destination in MODULE_FLAGS.items():

        module_group.add_argument(
            f"--{flag}",
            action="store_true",
            dest=destination,
            help=f"Run {flag} module",
        )

    parser.add_argument(
        "--check",
        action="store_true",
        help="Check external tool availability",
    )

    return parser


def get_selected_mode(
    args: argparse.Namespace,
) -> str:

    if getattr(
        args,
        "fast",
        False,
    ):
        return "fast"

    if getattr(
        args,
        "deep",
        False,
    ):
        return "deep"

    if getattr(
        args,
        "active",
        False,
    ):
        return "active"

    if getattr(
        args,
        "passive",
        False,
    ):
        return "passive"

    return "default"


def get_selected_modules(
    args: argparse.Namespace,
) -> set[str]:

    selected = set()

    for flag, module in MODULE_FLAGS.items():

        if getattr(
            args,
            flag,
            False,
        ):
            selected.add(
                module
            )

    # Active/passive are bundles.
    if getattr(
        args,
        "active",
        False,
    ):
        selected.add(
            "active"
        )

    if getattr(
        args,
        "passive",
        False,
    ):
        selected.add(
            "passive"
        )

    return selected


def print_tool_check() -> None:

    from enum4u.tools import create_default_registry

    registry = create_default_registry()

    print()
    print("=" * 60)
    print("                    ENUM4U TOOL HEALTH")
    print("=" * 60)

    ready = 0
    missing = 0

    for tool in sorted(
        registry.all(),
        key=lambda item: item.name,
    ):

        available = tool.check_available()

        status = _status(
            True,
            available,
        )

        if available:
            ready += 1
        else:
            missing += 1

        print(
            f"  {tool.name:<14} {status}"
        )

    print()
    print(
        f"  Ready   : {ready}"
    )
    print(
        f"  Missing : {missing}"
    )

    print("=" * 60)


def _get_mapping(
    context,
    key: str,
) -> dict:

    metadata = getattr(
        context,
        "metadata",
        {},
    )

    if not isinstance(
        metadata,
        dict,
    ):
        return {}

    value = metadata.get(
        key,
        {},
    )

    if isinstance(
        value,
        dict,
    ):
        return value

    return {}


def _get_status(
    data: dict,
    default: str = "unknown",
) -> str:

    return str(
        data.get(
            "status",
            default,
        )
    )


def _config_name(
    config: dict,
) -> str:

    meta = config.get(
        "_meta",
        {},
    )

    if not isinstance(
        meta,
        dict,
    ):
        return "DEFAULT"

    config_file = str(
        meta.get(
            "config_file",
            "",
        )
    )

    if not config_file:
        return "DEFAULT"

    name = (
        config_file
        .replace(
            "\\",
            "/",
        )
        .split("/")[-1]
    )

    if name.lower().endswith(
        ".yaml"
    ):
        name = name[:-5]

    elif name.lower().endswith(
        ".yml"
    ):
        name = name[:-4]

    return name.upper()


def _selected_tools(
    selected_modules: set[str],
    health: dict,
) -> set[str]:

    if not selected_modules:
        return set(
            health.keys()
        )

    visible = set()

    for module in selected_modules:

        visible.update(
            TOOL_MAP.get(
                module,
                set(),
            )
        )

    return visible


def print_report(
    context,
    config,
    mode,
    engine,
) -> None:

    selected_modules = set(
        getattr(
            engine,
            "selected_modules",
            set(),
        )
    )

    is_full_run = not selected_modules

    print()
    print("=" * 60)
    print("                         ENUM4U")
    print("          Unified Security Assessment Framework")
    print("=" * 60)

    print(
        f"Target : "
        f"{getattr(context, 'target', '')}"
    )

    display_mode = str(
        mode
    ).upper()

    if selected_modules:

        if len(selected_modules) == 1:
            display_mode = next(
                iter(selected_modules)
            ).upper()

    print(
        f"Mode   : "
        f"{display_mode}"
    )

    print(
        f"Config : "
        f"{_config_name(config)}"
    )

    metadata = getattr(
        context,
        "metadata",
        {},
    )

    if not isinstance(
        metadata,
        dict,
    ):
        metadata = {}

    print(
        f"Status : "
        f"{str(
            metadata.get(
                'status',
                'initialized',
            )
        ).upper()}"
    )

    engine_data = _get_mapping(
        context,
        "engine",
    )

    print(
        f"Engine : timeout="
        f"{engine_data.get('timeout', 0)}s "
        f"concurrency="
        f"{engine_data.get('concurrency', 0)}"
    )

    # =====================================================
    # TOOL HEALTH
    # =====================================================

    health = _get_mapping(
        context,
        "tool_health",
    )

    visible_tools = _selected_tools(
        selected_modules,
        health,
    )

    if health and visible_tools:

        print()
        print("Tool Health:")

        for name in sorted(
            visible_tools
        ):

            item = health.get(
                name,
                {},
            )

            if not isinstance(
                item,
                dict,
            ):
                item = {}

            status = _status(
                bool(
                    item.get(
                        "enabled",
                        True,
                    )
                ),
                bool(
                    item.get(
                        "available",
                        False,
                    )
                ),
            )

            print(
                f"  {name:<14} {status}"
            )

    # =====================================================
    # DATA
    # =====================================================

    subdomains = getattr(
        context,
        "subdomains",
        set(),
    )

    ips = getattr(
        context,
        "ips",
        set(),
    )

    try:
        subdomain_count = len(
            subdomains
        )
    except TypeError:
        subdomain_count = 0

    try:
        ip_count = len(
            ips
        )
    except TypeError:
        ip_count = 0

    ports = _get_mapping(
        context,
        "ports",
    )

    http = _get_mapping(
        context,
        "http",
    )

    crawl = _get_mapping(
        context,
        "crawl",
    )

    nuclei = _get_mapping(
        context,
        "nuclei",
    )

    risk = _get_mapping(
        context,
        "risk",
    )

    graph = _get_mapping(
        context,
        "graph",
    )

    ports_list = ports.get(
        "ports",
        [],
    )

    if not isinstance(
        ports_list,
        list,
    ):
        ports_list = []

    urls = crawl.get(
        "urls",
        [],
    )

    if not isinstance(
        urls,
        list,
    ):
        urls = []

    nuclei_findings = nuclei.get(
        "findings",
        [],
    )

    if not isinstance(
        nuclei_findings,
        list,
    ):
        nuclei_findings = []

    # =====================================================
    # RECON
    # =====================================================

    show_recon = (
        is_full_run
        or bool(
            selected_modules
            & {
                "recon",
                "dns",
                "subdomains",
                "certificates",
                "whois",
                "passive",
            }
        )
    )

    if show_recon:

        print()
        print("Recon:")

        print(
            f"  Subdomains : "
            f"{subdomain_count}"
        )

        print(
            f"  IPs        : "
            f"{ip_count}"
        )

        if ports:

            print(
                f"  Ports      : "
                f"{len(ports_list)} "
                f"({_get_status(ports)})"
            )

        if http:

            http_items = http.get(
                "results",
                http.get(
                    "endpoints",
                    [],
                ),
            )

            if not isinstance(
                http_items,
                list,
            ):
                http_items = []

            print(
                f"  HTTP       : "
                f"{len(http_items)} "
                f"({_get_status(http)})"
            )

        if crawl:

            print(
                f"  Crawled    : "
                f"{len(urls)} "
                f"({_get_status(crawl)})"
            )

        if nuclei:

            print(
                f"  Nuclei     : "
                f"{len(nuclei_findings)} "
                f"({_get_status(nuclei)})"
            )

    # =====================================================
    # PORTS
    # =====================================================

    if ports_list:

        print()
        print("Open/Detected Ports:")

        for item in ports_list:

            if not isinstance(
                item,
                dict,
            ):
                continue

            port = item.get(
                "port",
                "",
            )

            protocol = item.get(
                "protocol",
                "tcp",
            )

            state = item.get(
                "state",
                "unknown",
            )

            service = item.get(
                "service",
                "",
            )

            version = item.get(
                "version",
                "",
            )

            description = (
                f"{service} {version}"
            ).strip()

            print(
                f"  {port}/{protocol:<5} "
                f"{state:<10} "
                f"{description}"
            )

    # =====================================================
    # CRAWL
    # =====================================================

    show_crawl = (
        is_full_run
        or bool(
            selected_modules
            & {
                "web",
                "crawl",
            }
        )
    )

    if urls and show_crawl:

        print()
        print(
            "Crawled URLs "
            "(showing first 20):"
        )

        for url in urls[:20]:

            print(
                f"  {url}"
            )

    # =====================================================
    # RISK
    # =====================================================

    show_risk = (
        is_full_run
        or "nuclei" in selected_modules
        or "risk" in selected_modules
    )

    if risk and show_risk:

        print()
        print("Risk Assessment:")

        findings = risk.get(
            "findings",
            [],
        )

        if not isinstance(
            findings,
            list,
        ):
            findings = []

        print(
            f"  Findings   : "
            f"{len(findings)}"
        )

        print(
            f"  Status     : "
            f"{_get_status(risk)}"
        )

        if findings:

            for finding in findings[:10]:

                if not isinstance(
                    finding,
                    dict,
                ):
                    continue

                severity = str(
                    finding.get(
                        "severity",
                        "info",
                    )
                ).upper()

                name = finding.get(
                    "name",
                    finding.get(
                        "title",
                        "Unnamed finding",
                    ),
                )

                priority = finding.get(
                    "priority"
                )

                if priority:

                    print(
                        f"  [{severity}] "
                        f"{name} "
                        f"(priority={priority})"
                    )

                else:

                    print(
                        f"  [{severity}] "
                        f"{name}"
                    )

        else:

            print(
                "  No prioritized findings."
            )

    # =====================================================
    # GRAPH
    # =====================================================

    show_graph = (
        is_full_run
        or "graph" in selected_modules
    )

    if graph and show_graph:

        print()
        print("Attack Surface Graph:")

        print(
            f"  Nodes      : "
            f"{graph.get('node_count', 0)}"
        )

        print(
            f"  Edges      : "
            f"{graph.get('edge_count', 0)}"
        )

        print(
            f"  Status     : "
            f"{_get_status(graph)}"
        )

    # =====================================================
    # PIPELINE
    # =====================================================

    pipeline = _get_mapping(
        context,
        "pipeline",
    )

    if pipeline:

        completed = pipeline.get(
            "completed",
            [],
        )

        failed = pipeline.get(
            "failed",
            {},
        )

        skipped = pipeline.get(
            "skipped",
            0,
        )

        if not isinstance(
            completed,
            list,
        ):
            completed = []

        if not isinstance(
            failed,
            dict,
        ):
            failed = {}

        print()
        print("Pipeline Status:")

        print(
            f"  Completed : "
            f"{len(completed)}"
        )

        print(
            f"  Failed    : "
            f"{len(failed)}"
        )

        print(
            f"  Skipped   : "
            f"{skipped}"
        )

        print()
        print("Performance:")

        total_time = pipeline.get(
            "total_time",
            0.0,
        )

        task_count = pipeline.get(
            "task_count",
            0,
        )

        slowest_task = pipeline.get(
            "slowest_task",
        )

        slowest_time = pipeline.get(
            "slowest_time",
            0.0,
        )

        fastest_task = pipeline.get(
            "fastest_task",
        )

        fastest_time = pipeline.get(
            "fastest_time",
            0.0,
        )

        print(
            f"  Total Time      : "
            f"{float(total_time):.3f}s"
        )

        print(
            f"  Tasks           : "
            f"{task_count}"
        )

        if slowest_task:

            print(
                f"  Slowest Task    : "
                f"{slowest_task} "
                f"({float(slowest_time):.3f}s)"
            )

        if fastest_task:

            print(
                f"  Fastest Task    : "
                f"{fastest_task} "
                f"({float(fastest_time):.3f}s)"
            )

    print("=" * 60)


def main() -> None:

    parser = build_parser()
    args = parser.parse_args()

    if getattr(
        args,
        "check",
        False,
    ):

        print_tool_check()
        return

    if not args.target:

        print_index()
        parser.print_help()
        return

    mode = get_selected_mode(
        args
    )

    selected_modules = get_selected_modules(
        args
    )

    try:

        if args.deep:

            config_mode = "deep"

        elif args.fast:

            config_mode = "fast"

        elif args.passive:

            config_mode = "passive"

        else:

            config_mode = "default"

        config = load_config(
            config_mode
        )

        engine_kwargs = {
            "target": args.target,
            "mode": mode,
            "config": config,
        }

        if selected_modules:

            engine_kwargs[
                "selected_modules"
            ] = selected_modules

        engine = Engine(
            **engine_kwargs
        )

        initialize_pipeline(
            engine
        )

        context = engine.run()

    except ConfigError as exc:

        parser.error(
            str(exc)
        )

        return

    except TargetValidationError as exc:

        parser.error(
            str(exc)
        )

        return

    print_report(
        context=context,
        config=config,
        mode=mode,
        engine=engine,
    )

    try:

        json_path = generate_json_report(
            context,
            "output",
        )

        html_path = generate_html_report(
            context,
            "output",
        )

        print()

        print(
            f"JSON Report : "
            f"{json_path}"
        )

        print(
            f"HTML Report : "
            f"{html_path}"
        )

        print(
            "=" * 60
        )

    except Exception as exc:

        print()

        print(
            f"Report Error: "
            f"{exc}"
        )

        print(
            "=" * 60
        )


if __name__ == "__main__":
    main()