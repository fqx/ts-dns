# Repository security review — 2026-11-03

Reviewed all production Go packages, configuration examples, module dependencies,
and build workflows in `fqx/ts-dns` (base commit `a1cc733`). This is a source review
with regression tests, not a claim that the software or a deployment is free of
vulnerabilities. No deployment or exposed DNS listener was inspected.

## Verified issues fixed

| Area | Finding and mitigation | Regression coverage |
| --- | --- | --- |
| Proxied DNS/DoT | Concurrent calls shared and replaced one `dns.Conn`. Each call now owns and closes its connection, uses cancellable dialing, sets a deadline covering TLS handshake/read/write, and validates response ID, QR, opcode and question. | Concurrent pipe connections; malformed responses; stalled reads. |
| DoH | HTTP requests had no total timeout; bodies were read without a size bound. Added a five-second timeout, 65,535-byte DNS response limit, HTTP status and DNS response validation, disabled redirects, and require HTTPS endpoints. Context-aware dialers preserve cancellation. | Local HTTP server: valid/error/oversize/mismatched/stalled replies. |
| Cache | Keys omitted class and DNSSEC flags. `dns.Msg.SetReply` resets Rcode to NOERROR in the selected DNS library. Keys now include class, DO/CD/AD/RD and ECS; client-specific EDNS options/signatures bypass caching. Cached replies preserve Rcode and response flags, and are copied on insertion. Empty/multiple-question queries bypass caching. | Class/flag/cookie isolation, empty/multiple questions, cached NXDOMAIN+CNAME, AD/RA and transaction ID. |
| Rules | A remote or local rule could panic on invalid regex, regex metacharacters in wildcard domains, or overlapping short regex markers. Compile arbitrary regex safely, quote wildcard input, and check slice lengths. | Malformed wildcard and path rules. |
| GFWList | Unbounded download and ignored request/base64 lengths could accept invalid data or exhaust memory. Fetches now have time/size bounds, URL and redirect checks, exact base64 decoding, and reject lists without usable rules. Failed refreshes keep active rules. | Invalid/empty/oversize responses; immediate and periodic refresh; cancellation on stop. |
| Server startup | TCP and UDP listener goroutines assigned to the same error variable. Each listener now owns its error. | Race-enabled suite and build. |
| Example deployment | Wildcard listening can create an open recursive forwarder if deployed publicly. Examples now bind loopback. LAN deployment instructions require explicit listening and TCP/UDP firewall restrictions. | Configuration review. |

## Dependencies and supply chain

Updated the Go toolchain baseline to 1.27, DNS/TOML/logging/network/test modules,
and transitive dependencies. Replaced the obsolete `sparrc/go-ping` import path
with `prometheus-community/pro-bing`, and migrated test patches to gomonkey v2.
Existing module identity is retained for internal imports. Modules with no newer
upstream release remain pinned. `go mod verify` checks downloaded module integrity.

CI checks formatting, module integrity, vet, race-enabled tests, build, and
`govulncheck` v1.9.0. Actions are pinned to commit SHAs. Dependabot checks Go and
Actions weekly. Release writes are restricted to the tag-triggered publish job;
manual runs generate snapshot artifacts without publishing. GoReleaser v2 builds
archives and checksums without downloading mutable rule data into packages.

## Validation and limitations

Use Go 1.27.3 with:

```sh
go mod verify
go vet ./...
go test -race -gcflags=all=-l -timeout=90s ./...
go build ./...
govulncheck ./...
goreleaser check
goreleaser release --snapshot --clean
```

Confirmed locally: module integrity verification, full race-enabled test suite,
`go vet`, `go build`, actionlint v1.7.12, and GoReleaser v2.19.0 configuration
validation passed. Snapshot cross-build verification is recorded in the task
deliverables.

The legacy suite patches executable functions, so `-gcflags=all=-l` is required.
New security tests use local HTTP servers and in-memory connections.

The cloud network policy **denied** the scanner's request to
`https://vuln.go.dev/index/modules.json.gz` with `Forbidden`; therefore live
advisory scanning was attempted but did not complete. It must be rerun with that
host permitted, or by the configured GitHub Actions check. No clean advisory-scan
result or CVE remediation claim is made here.

GFWList updates replace memory only; a local file is an optional startup seed.
Until the first successful download, only local/custom rules are available.
HTTP URLs remain supported for compatibility; use HTTPS for rule integrity.
Configuration and local rule files are trusted administrator inputs. DoH now
rejects plaintext HTTP and URL credentials. Non-context custom proxy dialers are
rejected rather than allowed to block indefinitely; configured SOCKS5 dialers
support context cancellation.

There is no DNSSEC validation engine, source ACL, client authentication, or rate
limiter. DNSSEC flags are isolated in cache and upstream response fields are
preserved; this does not authenticate plaintext DNS upstreams. Deploy behind a
firewall and use encrypted upstreams when transport authenticity is required.
IPSet integration executes a fixed program with argument arrays, not a shell;
privileged IPSet/ICMP behavior was reviewed but was not exercised against a live
kernel/network. Cross-compiled artifacts require native smoke testing on their
target operating systems before production use.
