# Repository security review — 2026-11-03

Reviewed all production Go packages, configuration examples, module dependencies,
and build workflows in `fqx/ts-dns` (base commit `a1cc733`). This is a source review
with regression tests, not a claim that the software or a deployment is free of
vulnerabilities. No deployment or exposed DNS listener was inspected.

## Verified issues fixed

| Area | Finding and mitigation | Regression coverage |
| --- | --- | --- |
| Proxied DNS/DoT | Concurrent calls shared and replaced one `dns.Conn`. Each proxied call now owns and closes its connection, uses cancellable dialing, and sets a deadline covering TLS handshake/read/write. Both direct and proxied UDP/TCP/DoT replies validate response ID, QR, opcode and question. | Concurrent pipe connections; malformed responses; stalled reads; local UDP/TCP/DoT transport servers. |
| DoH | HTTP requests had no total timeout; bodies were read without a size bound. Added a five-second timeout, 65,535-byte DNS response limit, HTTP status and DNS response validation, disabled redirects, and require HTTPS endpoints. Context-aware dialers preserve cancellation. | Local HTTP server: valid/error/oversize/mismatched/stalled replies. |
| Cache | Keys omitted class, DNSSEC flags, OPT presence and UDP size. `SetReply` reset Rcode. Keys now isolate class, DO/CD/AD/RD, ECS, EDNS profiles and routing revision; client-specific EDNS options/signatures bypass caching. Non-NOERROR and truncated replies are not cached. Capacity is enforced under the insertion lock; replies are copied on insertion. Capturing the routing revision once isolates late replies from a previous GFWList. | Flag/class/cookie and EDNS profiles in both orders; UDP sizes; cache-enabled routing refresh; late old-revision replies; UDP truncation followed by TCP retry; CNAME+NXDOMAIN with short SOA negative TTL; concurrent capacity. |
| Rules | A remote or local rule could panic on invalid regex, regex metacharacters in wildcard domains, or overlapping short regex markers. Compile arbitrary regex safely, quote wildcard input, and check slice lengths. | Malformed wildcard and path rules. |
| GFWList | Unbounded download and ignored request/base64 lengths could accept invalid data or exhaust memory. Fetches now have time/size bounds, URL and redirect checks, exact base64 decoding, and reject lists without usable rules. Failed refreshes keep active rules and retry with bounded exponential backoff (one minute initially, fifteen-minute cap, never beyond the configured interval). Default startup uses a bundled checksum-recorded seed. | Invalid/empty/oversize responses; immediate and periodic refresh; cancellation on stop; offline seed; transient failure followed by recovery. |
| Server startup | TCP and UDP listener goroutines assigned to the same error variable. Each listener now owns its error. | Race-enabled suite and build. |
| Example deployment | Wildcard listening can create an open recursive forwarder if deployed publicly. Examples now bind loopback. LAN deployment instructions require explicit listening and TCP/UDP firewall restrictions. | Configuration review. |

## Dependencies and supply chain

Updated the minimum Go toolchain to 1.27.3, DNS/TOML/logging/network/test modules,
and transitive dependencies. Replaced the obsolete `sparrc/go-ping` import path
with `prometheus-community/pro-bing`, and migrated test patches to gomonkey v2.
Existing module identity is retained for internal imports. Modules with no newer
upstream release remain pinned. `go mod verify` checks downloaded module integrity.

CI and both release jobs select the latest patched 1.27.x toolchain.
CI checks formatting, module integrity, vet, race-enabled tests, build, and
`govulncheck` v1.9.0. Actions are pinned to commit SHAs. Dependabot checks Go and
Actions weekly. Release writes are restricted to the tag-triggered publish job;
manual runs generate snapshot artifacts without publishing. GoReleaser v2 builds
archives and checksums using the checked-in GFWList seed and its source/checksum
record; packaging does not download mutable rule data. The publish job requires
both a push event and a `v*` tag. Manual dispatch on a tag remains snapshot-only.

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
result is claimed from that blocked local attempt. The initial GitHub CI run on
commit `4330265` selected Go 1.27.0 and reported nine reachable standard-library
advisories. The workflows now select latest 1.27.x and the module requires at
least 1.27.3; the final pushed commit must pass the online scanner before a clean
result can be claimed.

GFWList updates replace memory only. Default configs load the bundled, checksum-
recorded local seed synchronously before serving queries; failed remote fetches
keep that seed active. After restart, the bundled seed is loaded again. Custom
configurations can provide a different local seed or explicitly use remote-only
mode. Seed provenance/checksum and release trigger conditions have regression
coverage, including manual dispatch on a version tag.
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
