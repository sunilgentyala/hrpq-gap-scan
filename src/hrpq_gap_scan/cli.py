from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict

from hrpq_gap_scan.models import GapReport, HostResult, ScopedCookie
from hrpq_gap_scan.report import analyze, diff_vantage_points
from hrpq_gap_scan.tls_probe import probe_host

SEVERITY_LABEL = {"high": "HIGH", "medium": "MEDIUM", "low": "LOW"}


def _print_report(report: GapReport) -> None:
    print(f"\nhrpq-gap-scan report for {report.apex}\n" + "=" * 60)
    for host, result in report.hosts.items():
        if not result.reachable:
            print(f"  {host}: unreachable ({result.error})")
            continue
        pq = "PQ hybrid" if result.pq_hybrid else "classical"
        hrpq = result.hrpq_header or "no HRPQ header"
        print(f"  {host}: {result.negotiated_group or 'unknown group'} [{pq}]  {hrpq}")

    if not report.findings:
        print("\nNo gaps found across the scanned hosts.")
        return

    print(f"\nFindings ({len(report.findings)}):")
    for finding in report.findings:
        print(f"  [{SEVERITY_LABEL[finding.severity]}] {finding.host}: {finding.detail}")


def _report_to_json(report: GapReport) -> dict:
    return {
        "apex": report.apex,
        "hosts": {
            host: {
                **{k: v for k, v in asdict(result).items() if k != "cookies"},
                "cookies": [asdict(c) for c in result.cookies],
            }
            for host, result in report.hosts.items()
        },
        "findings": [asdict(f) for f in report.findings],
    }


def _report_from_json(data: dict) -> GapReport:
    hosts = {
        host: HostResult(
            **{**h, "cookies": [ScopedCookie(**c) for c in h.get("cookies", [])]}
        )
        for host, h in data["hosts"].items()
    }
    return analyze(data["apex"], hosts)


def cmd_scan(args: argparse.Namespace) -> int:
    subdomains = list(args.subdomains or [])
    if args.subdomains_file:
        with open(args.subdomains_file, encoding="utf-8") as fh:
            subdomains.extend(line.strip() for line in fh if line.strip())

    all_hosts = [args.apex] + subdomains
    hosts: dict[str, HostResult] = {}
    for host in all_hosts:
        hosts[host] = probe_host(host, port=args.port, timeout=args.timeout)

    report = analyze(args.apex, hosts)

    if args.json:
        json.dump(_report_to_json(report), sys.stdout, indent=2)
        print()
    else:
        _print_report(report)

    return 1 if report.has_high_severity else 0


def cmd_diff(args: argparse.Namespace) -> int:
    with open(args.direct, encoding="utf-8") as fh:
        direct = _report_from_json(json.load(fh))
    with open(args.via_proxy, encoding="utf-8") as fh:
        via_proxy = _report_from_json(json.load(fh))

    findings = diff_vantage_points(direct, via_proxy)
    if not findings:
        print("No proxy-induced downgrade differences found between the two scans.")
        return 0

    print(f"Proxy vantage-point differences ({len(findings)}):")
    for finding in findings:
        print(f"  [{SEVERITY_LABEL[finding.severity]}] {finding.host}: {finding.detail}")
    return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hrpq-gap-scan",
        description="Audit a domain and its subdomains for the HRPQ / cookie-scoping "
        "post-quantum downgrade gap.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser(
        "scan", help="Probe an apex domain and its subdomains for the downgrade gap."
    )
    scan.add_argument("apex", help="Registrable domain to treat as the HRPQ apex, e.g. example.com")
    scan.add_argument("--subdomains", nargs="*", default=[], help="Subdomains to include, e.g. app.example.com")
    scan.add_argument("--subdomains-file", help="File with one subdomain per line")
    scan.add_argument("--port", type=int, default=443)
    scan.add_argument("--timeout", type=float, default=8.0)
    scan.add_argument("--json", action="store_true", help="Emit machine-readable JSON instead of a table")
    scan.set_defaults(func=cmd_scan)

    diff = subparsers.add_parser(
        "diff",
        help="Compare two saved JSON scans (e.g. direct vs. behind an enterprise "
        "TLS-inspecting proxy) to find proxy-induced downgrades.",
    )
    diff.add_argument("direct", help="JSON scan taken from an unproxied vantage point")
    diff.add_argument("via_proxy", help="JSON scan taken from behind the proxy")
    diff.set_defaults(func=cmd_diff)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
