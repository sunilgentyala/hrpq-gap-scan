# Examples

## Live scan

```bash
hrpq-gap-scan scan example.com --subdomains app.example.com legacy.example.com
```

## Sample output

`sample_scan_output.json` is the `--json` output for a fabricated apex domain where:

- `example.com` sends `Require-Post-Quantum` with `includeSubDomains` and sets a
  domain-scoped `session` cookie.
- `legacy.example.com` has not yet adopted PQ hybrid key agreement.

Running `analyze()` against that pair of hosts produces two high-severity findings:
the subdomain will hard-fail once HRPQ is enforced, and the `session` cookie is
exposed to injection from that same subdomain regardless of how strong
`example.com`'s own cryptography is. This is the exact gap the tool exists to catch
before it shows up in production traffic.

## Comparing an enterprise proxy path against a direct path

```bash
hrpq-gap-scan scan example.com --json > direct.json      # run from outside the proxy
hrpq-gap-scan scan example.com --json > via_proxy.json   # run from inside the proxied network
hrpq-gap-scan diff direct.json via_proxy.json
```

Any host that negotiates a PQ hybrid group directly but not through the proxy means
the TLS-inspecting proxy, not the origin server, is the actual downgrade vector.
