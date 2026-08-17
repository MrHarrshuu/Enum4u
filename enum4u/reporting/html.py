from __future__ import annotations

import html
from pathlib import Path


def _status_badge(status: str) -> str:
    status = str(
        status or "unknown"
    ).upper()

    if status in {
        "COMPLETED",
        "READY",
    }:
        css = "success"

    elif status in {
        "FAILED",
        "MISSING",
    }:
        css = "danger"

    elif status in {
        "SKIPPED",
        "DISABLED",
    }:
        css = "muted"

    else:
        css = "info"

    return (
        f'<span class="badge {css}">'
        f'{html.escape(status)}'
        f'</span>'
    )


def _confidence_badge(
    confidence: str,
) -> str:

    value = str(
        confidence or "unknown"
    ).lower()

    css = {
        "high": "success",
        "medium": "warning",
        "low": "muted",
    }.get(
        value,
        "info",
    )

    return (
        f'<span class="badge {css}">'
        f'{html.escape(value.upper())}'
        f'</span>'
    )


def _priority_badge(
    priority: str,
) -> str:

    value = str(
        priority or "info"
    ).lower()

    css = {
        "critical": "critical",
        "high": "danger",
        "medium": "warning",
        "low": "info",
        "info": "muted",
    }.get(
        value,
        "muted",
    )

    return (
        f'<span class="badge {css}">'
        f'{html.escape(value.upper())}'
        f'</span>'
    )


def generate_html_report(
    context,
    output_dir: str = "output",
) -> str:

    output_path = Path(
        output_dir
    )

    output_path.mkdir(
        parents=True,
        exist_ok=True,
    )

    target = html.escape(
        str(
            context.target
        )
    )

    mode = html.escape(
        str(
            getattr(
                context,
                "mode",
                "unknown",
            )
        ).upper()
    )

    status = str(
        context.metadata.get(
            "status",
            "unknown",
        )
    )

    # -------------------------------------------------
    # METADATA
    # -------------------------------------------------

    health = context.metadata.get(
        "tool_health",
        {},
    )

    ports = context.metadata.get(
        "ports",
        {},
    )

    http_data = context.metadata.get(
        "http",
        {},
    )

    crawl = context.metadata.get(
        "crawl",
        {},
    )

    recon = context.metadata.get(
        "recon",
        {},
    )

    dns = context.metadata.get(
        "dns",
        {},
    )

    nuclei = context.metadata.get(
        "nuclei",
        {},
    )

    risk = context.metadata.get(
        "risk",
        {},
    )

    graph = context.metadata.get(
        "graph",
        {},
    )

    intelligence = context.metadata.get(
        "intelligence",
        {},
    )

    enrichment = context.metadata.get(
        "enrichment",
        {},
    )

    certificates = context.metadata.get(
        "certificates",
        {},
    )

    whois = context.metadata.get(
        "whois",
        {},
    )

    tls = context.metadata.get(
        "tls",
        {},
    )

    technology = context.metadata.get(
        "technology",
        {},
    )

    services = context.metadata.get(
        "services",
        {},
    )

    pipeline = context.metadata.get(
        "pipeline",
        {},
    )

    # -------------------------------------------------
    # COLLECTIONS
    # -------------------------------------------------

    port_list = ports.get(
        "ports",
        [],
    )

    endpoints = context.metadata.get(
        "endpoints",
        [],
    )

    crawl_urls = crawl.get(
        "urls",
        [],
    )

    risk_findings = risk.get(
        "findings",
        [],
    )

    enriched_services = enrichment.get(
        "services",
        [],
    )

    detected_technologies = technology.get(
        "technologies",
        [],
    )

    # -------------------------------------------------
    # TOOL HEALTH
    # -------------------------------------------------

    tool_rows = []

    for name in sorted(
        health
    ):

        item = health.get(
            name,
            {},
        )

        enabled = item.get(
            "enabled",
            True,
        )

        available = item.get(
            "available",
            False,
        )

        if not enabled:
            tool_status = "DISABLED"

        elif available:
            tool_status = "READY"

        else:
            tool_status = "MISSING"

        tool_rows.append(
            f"""
            <tr>
                <td>{html.escape(name)}</td>
                <td>
                    {_status_badge(tool_status)}
                </td>
            </tr>
            """
        )

    # -------------------------------------------------
    # PORTS
    # -------------------------------------------------

    port_rows = []

    for item in port_list:

        port_rows.append(
            f"""
            <tr>
                <td>
                    {html.escape(
                        str(
                            item.get(
                                "port",
                                "",
                            )
                        )
                    )}
                </td>

                <td>
                    {html.escape(
                        str(
                            item.get(
                                "protocol",
                                "",
                            )
                        )
                    )}
                </td>

                <td>
                    {html.escape(
                        str(
                            item.get(
                                "state",
                                "",
                            )
                        )
                    )}
                </td>

                <td>
                    {html.escape(
                        str(
                            item.get(
                                "service",
                                "",
                            )
                        )
                    )}
                </td>

                <td>
                    {html.escape(
                        str(
                            item.get(
                                "version",
                                "",
                            )
                        )
                    )}
                </td>
            </tr>
            """
        )

    if not port_rows:

        port_rows.append(
            """
            <tr>
                <td colspan="5">
                    No port data
                </td>
            </tr>
            """
        )

    # -------------------------------------------------
    # ENDPOINTS
    # -------------------------------------------------

    endpoint_rows = []

    for endpoint in endpoints:

        endpoint_rows.append(
            f"""
            <tr>
                <td class="mono">
                    {html.escape(
                        str(endpoint)
                    )}
                </td>
            </tr>
            """
        )

    if not endpoint_rows:

        endpoint_rows.append(
            """
            <tr>
                <td>
                    No HTTP endpoints
                </td>
            </tr>
            """
        )

    # -------------------------------------------------
    # CRAWLED URLS
    # -------------------------------------------------

    crawl_rows = []

    for url in crawl_urls:

        crawl_rows.append(
            f"""
            <tr>
                <td class="mono">
                    {html.escape(
                        str(url)
                    )}
                </td>
            </tr>
            """
        )

    if not crawl_rows:

        crawl_rows.append(
            """
            <tr>
                <td>
                    No crawled URLs
                </td>
            </tr>
            """
        )

    # -------------------------------------------------
    # CVE / INTELLIGENCE ROWS
    # -------------------------------------------------

    cve_rows = []

    for service in enriched_services:

        for cve in service.get(
            "cves",
            [],
        ):

            cve_id = cve.get(
                "id",
                "",
            )

            description = cve.get(
                "description",
                "",
            )

            cvss = cve.get(
                "cvss"
            )

            if isinstance(
                cvss,
                dict,
            ):
                cvss_score = cvss.get(
                    "score"
                )

                severity = cvss.get(
                    "severity"
                )

            else:
                cvss_score = cvss
                severity = None

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
                "known_exploited",
                False,
            )

            confidence = cve.get(
                "intelligence_confidence",
                "unknown",
            )

            cve_rows.append(
                f"""
                <tr>

                    <td class="mono">
                        {html.escape(
                            str(cve_id)
                        )}
                    </td>

                    <td>
                        {html.escape(
                            str(
                                severity
                                or "unknown"
                            ).upper()
                        )}
                    </td>

                    <td>
                        {html.escape(
                            str(
                                cvss_score
                                if cvss_score
                                is not None
                                else "-"
                            )
                        )}
                    </td>

                    <td>
                        {html.escape(
                            str(
                                epss_score
                                if epss_score
                                is not None
                                else "-"
                            )
                        )}
                    </td>

                    <td>
                        {_status_badge(
                            "KNOWN EXPLOITED"
                            if kev
                            else "NOT IN KEV"
                        )}
                    </td>

                    <td>
                        {_confidence_badge(
                            confidence
                        )}
                    </td>

                    <td>
                        {html.escape(
                            str(
                                description
                            )[:240]
                        )}
                    </td>

                </tr>
                """
            )

    if not cve_rows:

        cve_rows.append(
            """
            <tr>
                <td colspan="7">
                    No enriched CVE data
                </td>
            </tr>
            """
        )

    # -------------------------------------------------
    # RISK FINDINGS
    # -------------------------------------------------

    risk_rows = []

    for finding in risk_findings:

        name = finding.get(
            "name",
            finding.get(
                "title",
                finding.get(
                    "id",
                    "Unnamed finding",
                ),
            ),
        )

        severity = finding.get(
            "severity",
            "unknown",
        )

        priority = finding.get(
            "priority",
            "info",
        )

        confidence = finding.get(
            "confidence",
            "low",
        )

        host = finding.get(
            "host",
            "",
        )

        risk_rows.append(
            f"""
            <tr>

                <td>
                    {html.escape(
                        str(name)
                    )}
                </td>

                <td>
                    {_status_badge(
                        str(
                            severity
                        )
                    )}
                </td>

                <td>
                    {_priority_badge(
                        priority
                    )}
                </td>

                <td>
                    {_confidence_badge(
                        confidence
                    )}
                </td>

                <td class="mono">
                    {html.escape(
                        str(host)
                    )}
                </td>

            </tr>
            """
        )

    if not risk_rows:

        risk_rows.append(
            """
            <tr>
                <td colspan="5">
                    No prioritized findings
                </td>
            </tr>
            """
        )

    # -------------------------------------------------
    # TECHNOLOGY ROWS
    # -------------------------------------------------

    technology_rows = []

    for item in detected_technologies:

        technology_rows.append(
            f"""
            <tr>
                <td>
                    {html.escape(
                        str(item)
                    )}
                </td>
            </tr>
            """
        )

    if not technology_rows:

        technology_rows.append(
            """
            <tr>
                <td>
                    No technology data
                </td>
            </tr>
            """
        )

    # -------------------------------------------------
    # HTML DOCUMENT
    # -------------------------------------------------

    html_content = f"""<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta name="viewport"
      content="width=device-width,
               initial-scale=1.0">

<title>
    Enum4u Security Assessment
</title>

<style>

:root {{
    --bg: #0b0f14;
    --panel: #111820;
    --border: #26313d;
    --text: #e8edf2;
    --muted: #8d9aa8;
    --accent: #42d392;
    --danger: #ff5c5c;
    --warning: #f5b942;
    --info: #55aaff;
    --critical: #ff3030;
}}

* {{
    box-sizing: border-box;
}}

body {{
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font-family:
        Inter,
        Segoe UI,
        Arial,
        sans-serif;
}}

.container {{
    width: min(1400px, 94%);
    margin: 40px auto;
}}

header {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 28px;
    margin-bottom: 24px;
}}

h1 {{
    margin: 0 0 8px;
    letter-spacing: 2px;
}}

h2 {{
    margin-top: 0;
}}

.subtitle {{
    color: var(--muted);
}}

.grid {{
    display: grid;
    grid-template-columns:
        repeat(
            auto-fit,
            minmax(170px, 1fr)
        );
    gap: 16px;
    margin-bottom: 24px;
}}

.card {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px;
}}

.metric {{
    font-size: 30px;
    font-weight: 700;
    margin-top: 8px;
}}

.label {{
    color: var(--muted);
    font-size: 13px;
    text-transform: uppercase;
    letter-spacing: 1px;
}}

section {{
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 22px;
    margin-bottom: 24px;
    overflow-x: auto;
}}

table {{
    width: 100%;
    border-collapse: collapse;
}}

th,
td {{
    padding: 11px 12px;
    text-align: left;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
}}

th {{
    color: var(--muted);
    font-size: 13px;
    text-transform: uppercase;
}}

.mono {{
    font-family:
        Consolas,
        "Courier New",
        monospace;
    word-break: break-all;
}}

.badge {{
    display: inline-block;
    padding: 4px 9px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 700;
}}

.success {{
    color: #07130d;
    background: var(--accent);
}}

.danger {{
    color: white;
    background: var(--danger);
}}

.warning {{
    color: #15100a;
    background: var(--warning);
}}

.critical {{
    color: white;
    background: var(--critical);
}}

.info {{
    color: white;
    background: var(--info);
}}

.muted {{
    color: var(--text);
    background: #59636e;
}}

footer {{
    color: var(--muted);
    text-align: center;
    padding: 20px;
}}

</style>

</head>

<body>

<div class="container">

<header>

    <h1>ENUM4U</h1>

    <div class="subtitle">
        Unified Security Assessment Framework
    </div>

    <p>
        <strong>Target:</strong>
        {target}
    </p>

    <p>
        <strong>Mode:</strong>
        {mode}

        &nbsp;&nbsp;

        <strong>Status:</strong>
        {_status_badge(status)}
    </p>

</header>

<!-- SUMMARY -->

<div class="grid">

<div class="card">
    <div class="label">
        Subdomains
    </div>

    <div class="metric">
        {recon.get(
            "count",
            recon.get(
                "subdomain_count",
                0,
            ),
        )}
    </div>
</div>

<div class="card">
    <div class="label">
        IPs
    </div>

    <div class="metric">
        {dns.get(
            "count",
            dns.get(
                "resolved_count",
                0,
            ),
        )}
    </div>
</div>

<div class="card">
    <div class="label">
        Ports
    </div>

    <div class="metric">
        {ports.get(
            "count",
            0,
        )}
    </div>
</div>

<div class="card">
    <div class="label">
        HTTP
    </div>

    <div class="metric">
        {http_data.get(
            "count",
            0,
        )}
    </div>
</div>

<div class="card">
    <div class="label">
        Crawled URLs
    </div>

    <div class="metric">
        {crawl.get(
            "count",
            0,
        )}
    </div>
</div>

<div class="card">
    <div class="label">
        Assets
    </div>

    <div class="metric">
        {intelligence.get(
            "asset_count",
            0,
        )}
    </div>
</div>

<div class="card">
    <div class="label">
        Relationships
    </div>

    <div class="metric">
        {intelligence.get(
            "relationship_count",
            0,
        )}
    </div>
</div>

<div class="card">
    <div class="label">
        CVEs
    </div>

    <div class="metric">
        {enrichment.get(
            "cve_count",
            0,
        )}
    </div>
</div>

<div class="card">
    <div class="label">
        EPSS
    </div>

    <div class="metric">
        {enrichment.get(
            "epss_count",
            0,
        )}
    </div>
</div>

<div class="card">
    <div class="label">
        KEV
    </div>

    <div class="metric">
        {enrichment.get(
            "kev_count",
            0,
        )}
    </div>
</div>

</div>

<!-- TOOL HEALTH -->

<section>

<h2>
    Tool Health
</h2>

<table>

<thead>
<tr>
    <th>Tool</th>
    <th>Status</th>
</tr>
</thead>

<tbody>
{"".join(tool_rows)}
</tbody>

</table>

</section>

<!-- PORTS -->

<section>

<h2>
    Detected Ports
</h2>

<table>

<thead>
<tr>
    <th>Port</th>
    <th>Protocol</th>
    <th>State</th>
    <th>Service</th>
    <th>Version</th>
</tr>
</thead>

<tbody>
{"".join(port_rows)}
</tbody>

</table>

</section>

<!-- INTELLIGENCE -->

<section>

<h2>
    Vulnerability Intelligence
</h2>

<table>

<thead>

<tr>
    <th>CVE</th>
    <th>Severity</th>
    <th>CVSS</th>
    <th>EPSS</th>
    <th>KEV</th>
    <th>Confidence</th>
    <th>Description</th>
</tr>

</thead>

<tbody>
{"".join(cve_rows)}
</tbody>

</table>

</section>

<!-- TECHNOLOGY -->

<section>

<h2>
    Detected Technologies
</h2>

<table>

<tbody>
{"".join(technology_rows)}
</tbody>

</table>

</section>

<!-- RISK -->

<section>

<h2>
    Risk Assessment
</h2>

<p>
    <strong>Findings:</strong>
    {risk.get("count", 0)}
</p>

<p>
    <strong>Status:</strong>
    {_status_badge(
        risk.get(
            "status",
            "unknown",
        )
    )}
</p>

<table>

<thead>

<tr>
    <th>Finding</th>
    <th>Severity</th>
    <th>Priority</th>
    <th>Confidence</th>
    <th>Host</th>
</tr>

</thead>

<tbody>
{"".join(risk_rows)}
</tbody>

</table>

</section>

<!-- NUCLEI -->

<section>

<h2>
    Nuclei Assessment
</h2>

<p>
    <strong>Status:</strong>
    {_status_badge(
        nuclei.get(
            "status",
            "unknown",
        )
    )}
</p>

<p>
    <strong>Findings:</strong>
    {nuclei.get(
        "count",
        0,
    )}
</p>

<p>
    <strong>Targets:</strong>
    {nuclei.get(
        "target_count",
        0,
    )}
</p>

</section>

<!-- GRAPH -->

<section>

<h2>
    Attack Surface Graph
</h2>

<div class="grid">

<div class="card">
    <div class="label">
        Nodes
    </div>

    <div class="metric">
        {graph.get(
            "node_count",
            0,
        )}
    </div>
</div>

<div class="card">
    <div class="label">
        Edges
    </div>

    <div class="metric">
        {graph.get(
            "edge_count",
            0,
        )}
    </div>
</div>

</div>

<p>
    <strong>Status:</strong>
    {_status_badge(
        graph.get(
            "status",
            "unknown",
        )
    )}
</p>

</section>

<!-- EXTENDED RECON -->

<section>

<h2>
    Extended Recon
</h2>

<table>

<tr>
    <th>Component</th>
    <th>Status</th>
</tr>

<tr>
    <td>Certificates</td>
    <td>
        {_status_badge(
            certificates.get(
                "status",
                "unknown",
            )
        )}
    </td>
</tr>

<tr>
    <td>WHOIS</td>
    <td>
        {_status_badge(
            whois.get(
                "status",
                "unknown",
            )
        )}
    </td>
</tr>

<tr>
    <td>TLS</td>
    <td>
        {_status_badge(
            tls.get(
                "status",
                "unknown",
            )
        )}
    </td>
</tr>

<tr>
    <td>Service Enumeration</td>
    <td>
        {_status_badge(
            services.get(
                "status",
                "unknown",
            )
        )}
    </td>
</tr>

</table>

</section>

<!-- ENDPOINTS -->

<section>

<h2>
    HTTP Endpoints
</h2>

<table>

<tbody>
{"".join(endpoint_rows)}
</tbody>

</table>

</section>

<!-- CRAWL -->

<section>

<h2>
    Crawled URLs
</h2>

<table>

<tbody>
{"".join(crawl_rows)}
</tbody>

</table>

</section>

<!-- PIPELINE -->

<section>

<h2>
    Pipeline
</h2>

<div class="grid">

<div class="card">
    <div class="label">
        Completed
    </div>

    <div class="metric">
        {len(
            pipeline.get(
                "completed",
                [],
            )
        )}
    </div>
</div>

<div class="card">
    <div class="label">
        Failed
    </div>

    <div class="metric">
        {len(
            pipeline.get(
                "failed",
                [],
            )
        )}
    </div>
</div>

<div class="card">
    <div class="label">
        Skipped
    </div>

    <div class="metric">
        {len(
            pipeline.get(
                "skipped",
                [],
            )
        )}
    </div>
</div>

<div class="card">
    <div class="label">
        Tasks
    </div>

    <div class="metric">
        {pipeline.get(
            "task_count",
            0,
        )}
    </div>
</div>

</div>

</section>

<footer>
    Generated by Enum4u
</footer>

</div>

</body>

</html>
"""

    report_file = (
        output_path
        / "enum4u-report.html"
    )

    report_file.write_text(
        html_content,
        encoding="utf-8",
    )

    return str(report_file)