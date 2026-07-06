"""Pure gap-analysis logic. No network I/O here, so this module is fully unit-testable.

The gap this project audits for, in one sentence: Chromium's HRPQ header lets a single
origin require post-quantum TLS, but cookies are scoped to the registrable domain, so
an origin's PQ guarantee is only as strong as its weakest sibling subdomain.
"""

from __future__ import annotations

from hrpq_gap_scan.models import Finding, GapReport, HostResult


def analyze(apex: str, hosts: dict[str, HostResult]) -> GapReport:
    findings: list[Finding] = []
    apex_result = hosts.get(apex)

    for host, result in hosts.items():
        if not result.reachable:
            findings.append(
                Finding(
                    severity="low",
                    kind="unreachable",
                    host=host,
                    detail="Could not complete a TLS handshake; verify manually before "
                    "treating this host as covered or excluded from HRPQ scope.",
                )
            )
            continue

        if not result.pq_hybrid:
            findings.append(
                Finding(
                    severity="medium",
                    kind="no-pq-hybrid",
                    host=host,
                    detail=f"Negotiated group was '{result.negotiated_group}', a classical "
                    "group. This host is a viable downgrade pivot until it supports a "
                    "PQ hybrid key agreement.",
                )
            )

    if apex_result and apex_result.hrpq_header:
        if not apex_result.include_subdomains:
            findings.append(
                Finding(
                    severity="high",
                    kind="hrpq-missing-includesubdomains",
                    host=apex,
                    detail="Require-Post-Quantum is set without includeSubDomains. "
                    "Cookie jars are shared across the registrable domain regardless of "
                    "this header, so any sibling subdomain that hasn't independently "
                    "adopted PQ can still inject or read domain-scoped cookies belonging "
                    f"to {apex}.",
                )
            )
        else:
            for host, result in hosts.items():
                if host == apex or not result.reachable:
                    continue
                if not result.pq_hybrid:
                    findings.append(
                        Finding(
                            severity="high",
                            kind="includesubdomains-breaks-subdomain",
                            host=host,
                            detail=f"{apex} sets includeSubDomains, but {host} does not "
                            "negotiate a PQ hybrid group. Browsers enforcing HRPQ have no "
                            "silent classical fallback here: connections to this host will "
                            "hard-fail rather than downgrade quietly.",
                        )
                    )

    pq_hosts = [h for h, r in hosts.items() if r.reachable and r.pq_hybrid]
    non_pq_hosts = [h for h, r in hosts.items() if r.reachable and not r.pq_hybrid]
    if non_pq_hosts:
        for host in pq_hosts:
            for cookie in hosts[host].cookies:
                if cookie.is_domain_scoped:
                    findings.append(
                        Finding(
                            severity="high",
                            kind="cookie-injection-exposure",
                            host=host,
                            detail=f"Cookie '{cookie.name}' is domain-scoped ("
                            f"Domain={cookie.domain_attr}) and set by a PQ hybrid-capable "
                            f"host, but {non_pq_hosts[0]} on the same registrable domain "
                            "is not PQ hybrid-capable. A downgrade attacker who reaches "
                            "that sibling can inject or overwrite this cookie regardless "
                            f"of {host}'s own cryptography.",
                        )
                    )

    findings.sort(key=lambda f: {"high": 0, "medium": 1, "low": 2}[f.severity])
    return GapReport(apex=apex, hosts=hosts, findings=findings)


def diff_vantage_points(direct: GapReport, via_proxy: GapReport) -> list[Finding]:
    """Compare a scan taken from an unproxied vantage point against one taken from
    behind an enterprise TLS-inspecting proxy, to surface the proxy-as-downgrade-vector
    failure mode: a host that negotiates PQ hybrid directly but not through the proxy.
    """
    findings: list[Finding] = []
    for host, direct_result in direct.hosts.items():
        proxied_result = via_proxy.hosts.get(host)
        if proxied_result is None:
            continue
        if direct_result.pq_hybrid and not proxied_result.pq_hybrid:
            reason = proxied_result.negotiated_group or (
                "unreachable" if not proxied_result.reachable else "unknown"
            )
            findings.append(
                Finding(
                    severity="high",
                    kind="proxy-downgrade-vector",
                    host=host,
                    detail=f"{host} negotiates a PQ hybrid group directly but the "
                    f"proxied path resolves to '{reason}'. The TLS-inspecting proxy on "
                    "this network path is the actual downgrade vector, not the origin "
                    "server. If HRPQ is enforced here, the proxied path will hard-fail "
                    "for roaming clients.",
                )
            )
    findings.sort(key=lambda f: {"high": 0, "medium": 1, "low": 2}[f.severity])
    return findings
