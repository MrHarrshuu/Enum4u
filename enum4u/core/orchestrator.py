from __future__ import annotations

from enum4u.core.engine import Engine
from enum4u.core.task import Task

from enum4u.tools import create_default_registry

from enum4u.modules.recon import (
    run_dns_recon,
    run_subdomain_recon,
    run_passive_recon,
    run_certificate_recon,
    run_whois_recon,
)

from enum4u.modules.enumeration import (
    run_http_enumeration,
    run_port_enumeration,
    run_service_enumeration,
    run_technology_enumeration,
    run_tls_enumeration,
)

from enum4u.modules.web import (
    run_crawling,
)

from enum4u.modules.assessment import (
    run_nuclei_assessment,
)

from enum4u.risk import (
    prioritize_findings,
)

from enum4u.graph import (
    build_attack_surface_graph,
)

from enum4u.intelligence import (
    correlate_assets,
    enrich_services,
)

from enum4u.utils.validation import (
    validate_target,
)


def initialize_pipeline(
    engine: Engine,
) -> None:

    registry = create_default_registry()

    # =====================================================
    # CORE TASKS
    # =====================================================

    def validation_task(context) -> None:
        normalized = validate_target(
            context.target
        )

        context.target = normalized

        context.add_asset(
            normalized
        )

        context.metadata[
            "target_valid"
        ] = True

    def initialization_task(context) -> None:
        context.metadata[
            "status"
        ] = "initialized"

        context.metadata[
            "tools"
        ] = registry.names()

    def tool_health_task(context) -> None:
        configured_tools = context.config.get(
            "tools",
            {},
        )

        health = {}

        for tool in registry.all():
            enabled = configured_tools.get(
                tool.name,
                True,
            )

            health[tool.name] = {
                "enabled": enabled,
                "available": tool.check_available(),
            }

        context.metadata[
            "tool_health"
        ] = health

    # =====================================================
    # RECON
    # =====================================================

    def subdomain_task(context) -> None:
        run_subdomain_recon(
            context
        )

    def dns_task(context) -> None:
        run_dns_recon(
            context
        )

    def passive_recon_task(context) -> None:
        run_passive_recon(
            context
        )

    def certificate_recon_task(context) -> None:
        run_certificate_recon(
            context
        )

    def whois_recon_task(context) -> None:
        run_whois_recon(
            context
        )

    # =====================================================
    # ENUMERATION
    # =====================================================

    def port_task(context) -> None:
        run_port_enumeration(
            context
        )

    def service_enumeration_task(context) -> None:
        run_service_enumeration(
            context
        )

    def http_task(context) -> None:
        run_http_enumeration(
            context
        )

    def technology_enumeration_task(context) -> None:
        run_technology_enumeration(
            context
        )

    def tls_enumeration_task(context) -> None:
        run_tls_enumeration(
            context
        )

    # =====================================================
    # WEB
    # =====================================================

    def crawling_task(context) -> None:
        run_crawling(
            context
        )

    # =====================================================
    # NUCLEI
    # =====================================================

    def nuclei_task(context) -> None:
        run_nuclei_assessment(
            context
        )

    # =====================================================
    # INTELLIGENCE
    # =====================================================

    def intelligence_correlation_task(
        context,
    ) -> None:

        result = correlate_assets(
            context
        )

        context.metadata[
            "intelligence"
        ] = result

    def intelligence_enrichment_task(
        context,
    ) -> None:

        result = enrich_services(
            context
        )

        context.metadata[
            "enrichment"
        ] = result

    # =====================================================
    # RISK
    # =====================================================

    def risk_task(context) -> None:

        unified_findings = []

        # -------------------------------------------------
        # NUCLEI FINDINGS
        # -------------------------------------------------

        nuclei = context.metadata.get(
            "nuclei",
            {},
        )

        nuclei_findings = nuclei.get(
            "findings",
            [],
        )

        if not isinstance(
            nuclei_findings,
            list,
        ):
            nuclei_findings = []

        for finding in nuclei_findings:

            if not isinstance(
                finding,
                dict,
            ):
                continue

            item = dict(
                finding
            )

            item.setdefault(
                "source",
                "Nuclei",
            )

            unified_findings.append(
                item
            )

        # -------------------------------------------------
        # ENRICHED CVE FINDINGS
        # -------------------------------------------------

        enrichment = context.metadata.get(
            "enrichment",
            {},
        )

        services = enrichment.get(
            "services",
            [],
        )

        if not isinstance(
            services,
            list,
        ):
            services = []

        for service in services:

            if not isinstance(
                service,
                dict,
            ):
                continue

            cves = service.get(
                "cves",
                [],
            )

            if not isinstance(
                cves,
                list,
            ):
                continue

            for cve in cves:

                if not isinstance(
                    cve,
                    dict,
                ):
                    continue

                cve_id = cve.get(
                    "id"
                )

                if not cve_id:
                    continue

                cvss = cve.get(
                    "cvss"
                )

                cvss_score = None
                cvss_severity = None

                if isinstance(
                    cvss,
                    dict,
                ):
                    cvss_score = cvss.get(
                        "score"
                    )

                    cvss_severity = cvss.get(
                        "severity"
                    )

                epss = cve.get(
                    "epss"
                )

                epss_score = None

                if isinstance(
                    epss,
                    dict,
                ):
                    epss_score = epss.get(
                        "epss"
                    )

                kev = cve.get(
                    "kev"
                )

                known_exploited = bool(
                    cve.get(
                        "known_exploited",
                        False,
                    )
                    or kev
                )

                finding = {
                    "id": cve_id,
                    "name": (
                        cve.get(
                            "description"
                        )
                        or cve_id
                    ),
                    "description": cve.get(
                        "description",
                        "",
                    ),
                    "severity": (
                        cvss_severity
                        or "unknown"
                    ),
                    "cvss": cvss_score,
                    "epss": epss_score,
                    "kev": kev,
                    "known_exploited": (
                        known_exploited
                    ),
                    "published": cve.get(
                        "published"
                    ),
                    "last_modified": cve.get(
                        "last_modified"
                    ),
                    "host": context.target,
                    "port": service.get(
                        "port"
                    ),
                    "protocol": service.get(
                        "protocol"
                    ),
                    "service": service.get(
                        "service"
                    ),
                    "version": service.get(
                        "version"
                    ),
                    "cpe": service.get(
                        "cpe"
                    ),
                    "source": "NVD",
                }

                unified_findings.append(
                    finding
                )

        # -------------------------------------------------
        # DEDUPLICATION
        # -------------------------------------------------

        unique = {}
        anonymous = []

        for finding in unified_findings:

            finding_id = str(
                finding.get(
                    "id",
                    "",
                )
            ).strip().upper()

            if finding_id:
                if finding_id not in unique:
                    unique[
                        finding_id
                    ] = finding
            else:
                anonymous.append(
                    finding
                )

        unified_findings = (
            list(
                unique.values()
            )
            + anonymous
        )

        prioritized = prioritize_findings(
            unified_findings
        )

        context.metadata[
            "risk"
        ] = {
            "status": "completed",
            "count": len(
                prioritized
            ),
            "findings": prioritized,
            "sources": {
                "nuclei": len(
                    nuclei_findings
                ),
                "cves": sum(
                    item.get(
                        "cve_count",
                        0,
                    )
                    for item in services
                    if isinstance(
                        item,
                        dict,
                    )
                ),
            },
        }

    # =====================================================
    # GRAPH
    # =====================================================

    def graph_task(context) -> None:

        graph = build_attack_surface_graph(
            context
        )

        context.metadata[
            "graph"
        ] = {
            "status": "completed",
            "node_count": len(
                graph.get(
                    "nodes",
                    [],
                )
            ),
            "edge_count": len(
                graph.get(
                    "edges",
                    [],
                )
            ),
            "data": graph,
        }

    # =====================================================
    # TASK DEFINITIONS
    # =====================================================

    tasks = {
        "target_validation": Task(
            name="target_validation",
            action=validation_task,
        ),

        "initialization": Task(
            name="initialization",
            action=initialization_task,
            depends_on=[
                "target_validation"
            ],
        ),

        "tool_health": Task(
            name="tool_health",
            action=tool_health_task,
            depends_on=[
                "initialization"
            ],
        ),

        # Recon
        "subdomain_recon": Task(
            name="subdomain_recon",
            action=subdomain_task,
            depends_on=[
                "tool_health"
            ],
        ),

        "dns_recon": Task(
            name="dns_recon",
            action=dns_task,
            depends_on=[
                "tool_health"
            ],
        ),

        "passive_recon": Task(
            name="passive_recon",
            action=passive_recon_task,
            depends_on=[
                "tool_health"
            ],
        ),

        "certificate_recon": Task(
            name="certificate_recon",
            action=certificate_recon_task,
            depends_on=[
                "passive_recon"
            ],
        ),

        "whois_recon": Task(
            name="whois_recon",
            action=whois_recon_task,
            depends_on=[
                "tool_health"
            ],
        ),

        # Enumeration
        "port_enumeration": Task(
            name="port_enumeration",
            action=port_task,
            depends_on=[
                "tool_health"
            ],
        ),

        "service_enumeration": Task(
            name="service_enumeration",
            action=service_enumeration_task,
            depends_on=[
                "port_enumeration"
            ],
        ),

        "http_enumeration": Task(
            name="http_enumeration",
            action=http_task,
            depends_on=[
                "port_enumeration"
            ],
        ),

        "technology_enumeration": Task(
            name="technology_enumeration",
            action=technology_enumeration_task,
            depends_on=[
                "http_enumeration"
            ],
        ),

        "tls_enumeration": Task(
            name="tls_enumeration",
            action=tls_enumeration_task,
            depends_on=[
                "port_enumeration"
            ],
        ),

        # Web
        "web_crawling": Task(
            name="web_crawling",
            action=crawling_task,
            depends_on=[
                "http_enumeration"
            ],
        ),

        # Assessment
        "nuclei_assessment": Task(
            name="nuclei_assessment",
            action=nuclei_task,
            depends_on=[
                "web_crawling"
            ],
        ),

        # Intelligence
        "intelligence_correlation": Task(
            name="intelligence_correlation",
            action=intelligence_correlation_task,
            depends_on=[
                "service_enumeration"
            ],
        ),

        "intelligence_enrichment": Task(
            name="intelligence_enrichment",
            action=intelligence_enrichment_task,
            depends_on=[
                "intelligence_correlation"
            ],
        ),

        # Risk
        "risk_analysis": Task(
            name="risk_analysis",
            action=risk_task,
            depends_on=[
                "intelligence_enrichment"
            ],
        ),

        # Graph
        "attack_surface_graph": Task(
            name="attack_surface_graph",
            action=graph_task,
            depends_on=[
                "risk_analysis"
            ],
        ),
    }

    # =====================================================
    # SELECTED MODULES
    # =====================================================

    selected = set(
        getattr(
            engine,
            "selected_modules",
            set(),
        )
    )

    # -----------------------------------------------------
    # No explicit module:
    # Preserve existing full pipeline behaviour.
    # -----------------------------------------------------

    if not selected:

        full_order = [
            "target_validation",
            "initialization",
            "tool_health",
            "subdomain_recon",
            "dns_recon",
            "port_enumeration",
            "http_enumeration",
            "web_crawling",
            "passive_recon",
            "certificate_recon",
            "whois_recon",
            "service_enumeration",
            "technology_enumeration",
            "tls_enumeration",
            "nuclei_assessment",
            "intelligence_correlation",
            "intelligence_enrichment",
            "risk_analysis",
            "attack_surface_graph",
        ]

        for name in full_order:
            engine.register_task(
                tasks[name]
            )

        return

    # =====================================================
    # MODULE GROUPS
    # =====================================================

    groups = {
        "recon": {
            "subdomain_recon",
            "dns_recon",
            "passive_recon",
            "certificate_recon",
            "whois_recon",
        },

        "active": {
            "subdomain_recon",
            "dns_recon",
            "port_enumeration",
            "service_enumeration",
            "http_enumeration",
            "technology_enumeration",
            "tls_enumeration",
            "web_crawling",
        },

        "passive": {
            "passive_recon",
            "certificate_recon",
            "whois_recon",
            "dns_recon",
            "subdomain_recon",
        },

        "web": {
            "http_enumeration",
            "web_crawling",
        },
    }

    requested = set()

    for module in selected:

        if module in groups:
            requested.update(
                groups[module]
            )

        elif module == "crawl":
            requested.add(
                "web_crawling"
            )

        elif module == "ports":
            requested.add(
                "port_enumeration"
            )

        elif module == "services":
            requested.add(
                "service_enumeration"
            )

        elif module == "technology":
            requested.add(
                "technology_enumeration"
            )

        elif module == "tls":
            requested.add(
                "tls_enumeration"
            )

        elif module == "nuclei":
            requested.add(
                "nuclei_assessment"
            )

        elif module == "risk":
            requested.add(
                "risk_analysis"
            )

        elif module == "graph":
            requested.add(
                "attack_surface_graph"
            )

        elif module == "dns":
            requested.add(
                "dns_recon"
            )

        elif module == "subdomains":
            requested.add(
                "subdomain_recon"
            )

        elif module == "certificates":
            requested.add(
                "certificate_recon"
            )

        elif module == "whois":
            requested.add(
                "whois_recon"
            )

    # =====================================================
    # DEPENDENCY CLOSURE
    # =====================================================

    included = set(
        requested
    )

    changed = True

    while changed:

        changed = False

        for name in list(
            included
        ):

            for dependency in tasks[
                name
            ].depends_on:

                if dependency not in included:
                    included.add(
                        dependency
                    )

                    changed = True

    # =====================================================
    # REGISTRATION ORDER
    # =====================================================

    order = [
        "target_validation",
        "initialization",
        "tool_health",
        "subdomain_recon",
        "dns_recon",
        "passive_recon",
        "certificate_recon",
        "whois_recon",
        "port_enumeration",
        "service_enumeration",
        "http_enumeration",
        "technology_enumeration",
        "tls_enumeration",
        "web_crawling",
        "nuclei_assessment",
        "intelligence_correlation",
        "intelligence_enrichment",
        "risk_analysis",
        "attack_surface_graph",
    ]

    for name in order:

        if name in included:
            engine.register_task(
                tasks[name]
            )