from hrpq_gap_scan.models import HostResult, ScopedCookie
from hrpq_gap_scan.report import analyze, diff_vantage_points


def _host(
    host,
    reachable=True,
    negotiated_group="X25519MLKEM768",
    pq_hybrid=True,
    hrpq_header=None,
    include_subdomains=False,
    cookies=None,
    error=None,
):
    return HostResult(
        host=host,
        reachable=reachable,
        negotiated_group=negotiated_group,
        pq_hybrid=pq_hybrid,
        hrpq_header=hrpq_header,
        include_subdomains=include_subdomains,
        cookies=cookies or [],
        error=error,
    )


def test_no_findings_when_everything_is_pq_hybrid_and_covered():
    hosts = {
        "example.com": _host("example.com", hrpq_header="max-age=31536000; includeSubDomains", include_subdomains=True),
        "app.example.com": _host("app.example.com"),
    }
    report = analyze("example.com", hosts)
    assert report.findings == []
    assert not report.has_high_severity


def test_hrpq_without_includesubdomains_is_flagged_high():
    hosts = {
        "example.com": _host("example.com", hrpq_header="max-age=31536000"),
    }
    report = analyze("example.com", hosts)
    kinds = {f.kind for f in report.findings}
    assert "hrpq-missing-includesubdomains" in kinds
    assert report.has_high_severity


def test_includesubdomains_breaks_non_pq_subdomain():
    hosts = {
        "example.com": _host(
            "example.com", hrpq_header="max-age=31536000; includeSubDomains", include_subdomains=True
        ),
        "legacy.example.com": _host("legacy.example.com", negotiated_group="X25519", pq_hybrid=False),
    }
    report = analyze("example.com", hosts)
    breakage = [f for f in report.findings if f.kind == "includesubdomains-breaks-subdomain"]
    assert len(breakage) == 1
    assert breakage[0].host == "legacy.example.com"


def test_domain_scoped_cookie_flagged_when_sibling_lacks_pq():
    session_cookie = ScopedCookie(name="session", domain_attr=".example.com", secure=True, http_only=True)
    hosts = {
        "example.com": _host("example.com", cookies=[session_cookie]),
        "legacy.example.com": _host("legacy.example.com", negotiated_group="X25519", pq_hybrid=False),
    }
    report = analyze("example.com", hosts)
    exposures = [f for f in report.findings if f.kind == "cookie-injection-exposure"]
    assert len(exposures) == 1
    assert "session" in exposures[0].detail


def test_host_only_cookie_not_flagged():
    host_only_cookie = ScopedCookie(name="csrf", domain_attr=None, secure=True, http_only=True)
    hosts = {
        "example.com": _host("example.com", cookies=[host_only_cookie]),
        "legacy.example.com": _host("legacy.example.com", negotiated_group="X25519", pq_hybrid=False),
    }
    report = analyze("example.com", hosts)
    assert not any(f.kind == "cookie-injection-exposure" for f in report.findings)


def test_unreachable_host_is_low_severity_only():
    hosts = {"example.com": _host("example.com", reachable=False, negotiated_group=None, pq_hybrid=False, error="timed out")}
    report = analyze("example.com", hosts)
    assert len(report.findings) == 1
    assert report.findings[0].severity == "low"
    assert not report.has_high_severity


def test_diff_vantage_points_flags_proxy_downgrade():
    direct = analyze("example.com", {"example.com": _host("example.com")})
    via_proxy = analyze(
        "example.com",
        {"example.com": _host("example.com", negotiated_group="X25519", pq_hybrid=False)},
    )
    findings = diff_vantage_points(direct, via_proxy)
    assert len(findings) == 1
    assert findings[0].kind == "proxy-downgrade-vector"


def test_diff_vantage_points_no_findings_when_consistent():
    direct = analyze("example.com", {"example.com": _host("example.com")})
    via_proxy = analyze("example.com", {"example.com": _host("example.com")})
    assert diff_vantage_points(direct, via_proxy) == []
