"""Network probing: negotiated TLS 1.3 group via OpenSSL, plus HTTP response headers
and Set-Cookie attributes via a plain HTTPS request.

This performs the same class of read-only, passive checks a browser or a tool like
testssl.sh already makes; it does not attempt to bypass, exploit, or interfere with
anything. Only scan hosts you own or are authorized to test.
"""

from __future__ import annotations

import http.client
import re
import shutil
import ssl
import subprocess

from hrpq_gap_scan.groups import DEFAULT_GROUP_PREFERENCE, is_pq_hybrid
from hrpq_gap_scan.models import HostResult, ScopedCookie

_NEGOTIATED_GROUP_RE = re.compile(r"Negotiated TLS1\.3 group:\s*(\S+)")
_COOKIE_DOMAIN_RE = re.compile(r"Domain=([^;]+)", re.IGNORECASE)


def openssl_available() -> bool:
    return shutil.which("openssl") is not None


def probe_negotiated_group(host: str, port: int = 443, timeout: float = 8.0) -> str | None:
    """Shell out to `openssl s_client` and parse the negotiated TLS 1.3 group.

    OpenSSL 3.2+ prints a "Negotiated TLS1.3 group: <name>" line when the -groups
    list includes PQ hybrid names, which is how we distinguish "server offered PQ but
    the handshake landed on classical anyway" from "server never offered PQ".
    """
    if not openssl_available():
        raise RuntimeError(
            "openssl not found on PATH; install OpenSSL 3.2+ to probe negotiated groups"
        )

    groups_arg = ":".join(DEFAULT_GROUP_PREFERENCE)
    cmd = [
        "openssl",
        "s_client",
        "-connect",
        f"{host}:{port}",
        "-servername",
        host,
        "-groups",
        groups_arg,
        "-brief",
    ]
    try:
        proc = subprocess.run(
            cmd,
            input="",
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return None

    output = proc.stdout + proc.stderr
    if "SSL_CONF_cmd" in output and "-groups" in output:
        raise RuntimeError(
            "local openssl build rejected the -groups list; it may be older than "
            "3.2 and not recognize ML-KEM hybrid group names"
        )

    match = _NEGOTIATED_GROUP_RE.search(output)
    return match.group(1) if match else None


def fetch_headers_and_cookies(
    host: str, port: int = 443, timeout: float = 8.0
) -> tuple[str | None, bool, list[ScopedCookie]]:
    """Issue a plain HTTPS GET and return (hrpq_header_value, include_subdomains, cookies)."""
    ctx = ssl.create_default_context()
    conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    try:
        conn.request("GET", "/", headers={"Host": host, "User-Agent": "hrpq-gap-scan"})
        resp = conn.getresponse()
        hrpq_value = resp.getheader("Require-Post-Quantum")
        include_subdomains = bool(hrpq_value and "includeSubDomains" in hrpq_value)

        cookies: list[ScopedCookie] = []
        for header_name, header_value in resp.getheaders():
            if header_name.lower() != "set-cookie":
                continue
            name = header_value.split("=", 1)[0].strip()
            domain_match = _COOKIE_DOMAIN_RE.search(header_value)
            cookies.append(
                ScopedCookie(
                    name=name,
                    domain_attr=domain_match.group(1).strip() if domain_match else None,
                    secure="secure" in header_value.lower(),
                    http_only="httponly" in header_value.lower(),
                )
            )
        return hrpq_value, include_subdomains, cookies
    finally:
        conn.close()


def probe_host(host: str, port: int = 443, timeout: float = 8.0) -> HostResult:
    """Run both probes against one host and assemble a HostResult."""
    try:
        negotiated_group = probe_negotiated_group(host, port, timeout)
        hrpq_header, include_subdomains, cookies = fetch_headers_and_cookies(
            host, port, timeout
        )
    except Exception as exc:  # noqa: BLE001 - surfaced to the user as HostResult.error
        return HostResult(host=host, reachable=False, error=str(exc))

    return HostResult(
        host=host,
        reachable=True,
        negotiated_group=negotiated_group,
        pq_hybrid=is_pq_hybrid(negotiated_group),
        hrpq_header=hrpq_header,
        include_subdomains=include_subdomains,
        cookies=cookies,
    )
