"""Data structures shared between the network probe and the gap analysis."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ScopedCookie:
    """A Set-Cookie observed on a host, with the attributes that matter for scoping."""

    name: str
    domain_attr: str | None  # the `Domain=` attribute value, or None if host-only
    secure: bool
    http_only: bool

    @property
    def is_domain_scoped(self) -> bool:
        return self.domain_attr is not None


@dataclass
class HostResult:
    """What a single probe pass observed for one host."""

    host: str
    reachable: bool
    negotiated_group: str | None = None
    pq_hybrid: bool = False
    hrpq_header: str | None = None  # raw Require-Post-Quantum header value, if present
    include_subdomains: bool = False
    cookies: list[ScopedCookie] = field(default_factory=list)
    error: str | None = None


@dataclass
class Finding:
    """One gap the analysis flagged, ranked by severity."""

    severity: str  # "high", "medium", "low"
    kind: str
    host: str
    detail: str


@dataclass
class GapReport:
    apex: str
    hosts: dict[str, HostResult]
    findings: list[Finding]

    @property
    def has_high_severity(self) -> bool:
        return any(f.severity == "high" for f in self.findings)
