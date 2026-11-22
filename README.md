# dnsprobe

DNS record prober with Nagios-style exit codes, built for cron alerts and
CI pipelines: "are my names still resolving, and do all my resolvers agree?"
answered in one line, machine-readable, zero dependencies.

Pure Go, stdlib only (`net`, `encoding/binary`). Cross-platform:
Linux, macOS, Windows.

## Install

```sh
go install github.com/thejedi433/dnsprobe/cmd/dnsprobe@latest
```

## Usage

```sh
dnsprobe example.com                          # A records via system resolvers
dnsprobe -type MX mail.example.com            # any record type
dnsprobe -servers 8.8.8.8,1.1.1.1 a.example   # explicit resolvers
dnsprobe -type AAAA google.com                # IPv6
dnsprobe -json example.com                    # JSON for dashboards
dnsprobe -t 2s -retries 1 example.com         # faster budget
dnsprobe -q example.com                       # no stderr progress line
dnsprobe -type PTR 1.2.3.4.in-addr.arpa       # reverse lookups
```

Supported types: `A, AAAA, CNAME, NS, PTR, MX, TXT, SOA`.

Output is dig-style, one block per resolver:

```
;; SERVER: 8.8.8.8:53 (NOERROR) - rtt 55.43ms - A
example.com A 300 104.20.23.154
example.com A 300 172.66.147.243
```

When several resolvers return different rcodes for the same name (one
answers, another says NXDOMAIN/SERVFAIL — a split-horizon or broken-view
signal), a `;; WARNING: servers disagree: ...` footer is printed. Record
*values* are not compared: public resolvers legitimately differ via
round-robin and ECS.

Truncated UDP answers (large TXT sets etc.) are automatically retried over
TCP, per RFC 1035 4.2.1.

## Exit codes

| code | meaning                                             |
|------|-----------------------------------------------------|
| 0    | all resolvers answered NOERROR                      |
| 1    | a resolver answered with a non-NOERROR rcode (NXDOMAIN, SERVFAIL, ...) |
| 2    | transport/parse failure, or a usage error           |

A cron job is as simple as:

```cron
*/30 * * * * cd /srv && dnsprobe -q a.example b.example >/dev/null 2>&1 || logger dnsprobe-alert
```

or as a CI step guarding your zone file:

```yaml
- run: go run github.com/thejedi433/dnsprobe/cmd/dnsprobe@latest -q -type SOA example.com
```

## Design notes

- The wire codec lives in `internal/dns` (RFC 1035 label/name encoding,
  compression pointers with loop guards per RFC 5343 3.3.3, record types
  A/AAAA/CNAME/NS/PTR/MX/TXT/SOA, RFC 3597 generic format for unknown
  types).
- `internal/probe` runs UDP exchanges with deadline clamping from the
  context and TCP fallback on TC.
- `internal/report` owns the exit-code rules and both output renderings.
- Default resolvers come from `/etc/resolv.conf` where it exists; on
  systems without it the fallback is `8.8.8.8` (pass `-servers` to be
  explicit).
- No DNSSEC validation and no TLS: this tool is a diagnostic, not a
  security boundary. Query IDs are time-derived rather than cryptographic
  because answers arrive on a socket the tool itself opened.

## Development

```sh
go test ./...            # all tests are hermetic (fake in-process resolvers)
go vet ./... && gofmt -l .
```
