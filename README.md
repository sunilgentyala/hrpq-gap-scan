# hrpq-gap-scan

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![Site](https://img.shields.io/badge/site-sunilgentyala.github.io%2Fhrpq--gap--scan-0b5fff.svg)](https://sunilgentyala.github.io/hrpq-gap-scan/)
[![SC World](https://img.shields.io/badge/SC%20World-perspective%20piece-orange.svg)](https://www.scworld.com/perspective/post-quantum-https-migration-faces-enterprise-browser-challenges)

**Audits a domain and its subdomains for the HRPQ / cookie-scoping post-quantum
downgrade gap in Chromium's [Post-Quantum HTTPS Authentication
Roadmap](https://www.chromium.org/Home/chromium-security/post-quantum-auth-roadmap/).**

Project site: **https://sunilgentyala.github.io/hrpq-gap-scan/**

## The gap this tool audits for

Chromium's roadmap adds a `Require-Post-Quantum` (HRPQ) response header so a site can
tell the browser "refuse anything but a post-quantum key exchange for this origin,"
modeled directly on how HSTS works today. That model is sound at the origin level.
It breaks at the domain level, because cookies were never designed to respect origin
boundaries the way HRPQ does:

- **Cookie scoping ignores HRPQ.** A domain-scoped cookie set by a PQ-protected
  origin is still readable by, and can still be overwritten by, any sibling
  subdomain on the same registrable domain that hasn't adopted PQ yet. Protecting
  one origin with HRPQ doesn't protect that origin's session state if a sibling is
  still exploitable.
- **`includeSubDomains` is an all-or-nothing switch.** Set it, and any subdomain
  that isn't PQ hybrid-capable yet hard-fails for every client that enforces HRPQ,
  with no silent classical fallback. Leave it off, and the cookie-injection gap
  above stays wide open.
- **Enterprise TLS-inspecting proxies are an independent, often-invisible
  migration target.** A proxy that terminates and re-originates TLS has to support
  the same hybrid key agreement as the origin it fronts, or HRPQ-enforcing clients
  roaming between a proxied and unproxied network will see connections fail and
  recover with no obvious explanation.

None of this is a defect in HRPQ as specified. It's a structural mismatch between a
per-origin security guarantee and a per-domain state model, and it's the kind of gap
that's invisible until an incident forces you to find it. `hrpq-gap-scan` turns that
gap into something you can check for before that happens.

This toolkit is the operational companion to the SC World perspective piece
["Post-quantum HTTPS migration faces enterprise browser
challenges"](https://www.scworld.com/perspective/post-quantum-https-migration-faces-enterprise-browser-challenges)
by Sunil Gentyala (July 2026), which lays out the same cookie-scoping,
`includeSubDomains`, and enterprise-proxy gaps in narrative form for a
practitioner audience.

## What it checks

For an apex domain and a set of subdomains, `hrpq-gap-scan` probes each host for:

1. Whether the host negotiates a **PQ hybrid TLS 1.3 group** (`X25519MLKEM768` and
   related hybrids) rather than silently landing on a classical group.
2. Whether the host sends an **HRPQ header**, and whether `includeSubDomains` is set.
3. **Domain-scoped cookies** (`Set-Cookie: ...; Domain=...`) and whether any sibling
   host on the same registrable domain lacks PQ hybrid support, which makes that
   cookie a viable injection target regardless of how strong the issuing host's own
   cryptography is.

It then reports concrete findings, ranked by severity, instead of a raw pass/fail:

| Finding | Severity | Meaning |
|---|---|---|
| `hrpq-missing-includesubdomains` | high | HRPQ is set without `includeSubDomains`; siblings can still inject cookies into this origin's session state |
| `includesubdomains-breaks-subdomain` | high | `includeSubDomains` is set, but a subdomain isn't PQ-capable and will hard-fail once HRPQ is enforced |
| `cookie-injection-exposure` | high | A domain-scoped cookie from a PQ-capable host is exposed to a non-PQ-capable sibling |
| `no-pq-hybrid` | medium | Host negotiated a classical group; a downgrade pivot point until upgraded |
| `proxy-downgrade-vector` | high | A host negotiates PQ hybrid directly but not through an enterprise proxy path (via `diff`) |
| `unreachable` | low | Host couldn't be probed; verify manually |

## Install

```bash
pip install -e .
```

Requires OpenSSL 3.2+ on `PATH` (used to read the actual negotiated TLS 1.3 group;
Python's own `ssl` module doesn't expose this for TLS 1.3).

## Usage

```bash
# Scan an apex domain and its subdomains
hrpq-gap-scan scan example.com --subdomains app.example.com legacy.example.com

# Machine-readable output
hrpq-gap-scan scan example.com --subdomains-file subdomains.txt --json > scan.json

# Detect a TLS-inspecting proxy as the downgrade vector by diffing two vantage points
hrpq-gap-scan scan example.com --json > direct.json      # from outside the proxy
hrpq-gap-scan scan example.com --json > via_proxy.json   # from inside the proxied network
hrpq-gap-scan diff direct.json via_proxy.json
```

See [`examples/`](examples/) for a full walkthrough and sample output.

Only scan domains you own or are authorized to test. Every check here is a passive,
read-only TLS handshake and HTTP header fetch, the same class of check a browser or
`testssl.sh` already performs; nothing here bypasses, exploits, or interferes with
the target.

## Architecture

- `groups.py` — known classical and PQ hybrid TLS 1.3 group names.
- `tls_probe.py` — network layer: negotiated group via `openssl s_client`, headers
  and cookies via a plain HTTPS request.
- `report.py` — pure gap-analysis logic, fully unit-tested with no network I/O.
- `cli.py` — `scan` and `diff` subcommands.

## Running the tests

```bash
pip install -e . pytest
pytest
```

## Author

**Sunil Gentyala** is a cybersecurity architect and researcher, IEEE Senior Member,
and HCLTech's expert representative to the Cloud Security Alliance, specializing in
post-quantum, AI, and agentic-system security.

## Docker (GitHub Packages)

A prebuilt container image is published to the GitHub Container Registry:

```bash
docker pull ghcr.io/sunilgentyala/hrpq-gap-scan:latest
docker run --rm ghcr.io/sunilgentyala/hrpq-gap-scan scan example.com
```

## How to Cite

If you use hrpq-gap-scan in your research, please cite the software:

```bibtex
@software{gentyala2026hrpq,
  author    = {Gentyala, Sunil},
  title     = {hrpq-gap-scan},
  year      = {2026},
  url       = {https://github.com/sunilgentyala/hrpq-gap-scan}
}
```

Machine-readable metadata is in [`CITATION.cff`](CITATION.cff); GitHub shows it under "Cite this repository".

## License

MIT, see [LICENSE](LICENSE).
