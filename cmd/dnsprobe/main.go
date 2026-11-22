// Command dnsprobe queries DNS records of any type against one or more
// resolvers and exits with a Nagios-style status code (0 ok, 1 answered
// with a non-NOERROR rcode, 2 transport/parse failure), so it can drive
// cron alerts and CI pipelines. It also cross-compares answers between
// servers to catch split-horizon or inconsistent views. Pure Go, stdlib
// only.
//
// Usage:
//
//	dnsprobe [-json] [-type T] [-servers h[,h...]] [-timeout d] [-retries n] [-parallel n] NAME [NAME...]
package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/thejedi433/dnsprobe/internal/dns"
	"github.com/thejedi433/dnsprobe/internal/report"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	code, err := run(ctx, os.Args[1:], os.Stdout, systemResolvers)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dnsprobe:", err)
		os.Exit(2)
	}
	os.Exit(code)
}

// run parses args, queries, writes output, and returns the exit code.
// resolversFunc supplies the default servers when -servers is absent
// (injected so tests stay hermetic).
func run(ctx context.Context, args []string, stdout io.Writer, resolversFunc func() []string) (int, error) {
	out := bufio.NewWriter(stdout)
	fs, opts := newFlagSet(out)
	if err := fs.Parse(args); err != nil {
		_ = out.Flush() // flag package wrote usage into out
		return 2, err
	}
	names := fs.Args()
	if len(names) == 0 {
		_ = out.Flush()
		fs.Usage()
		return 2, fmt.Errorf("no names given")
	}
	qtype, ok := dns.TypeByName[strings.ToUpper(opts.typeName)]
	if !ok {
		_ = out.Flush()
		return 2, fmt.Errorf("unknown -type %q (want A, AAAA, CNAME, MX, NS, PTR, SOA, TXT)", opts.typeName)
	}
	if opts.retries < 0 || opts.retries > 5 {
		_ = out.Flush()
		return 2, fmt.Errorf("-retries must be 0-5")
	}
	if opts.parallel < 1 || opts.parallel > 64 {
		_ = out.Flush()
		return 2, fmt.Errorf("-parallel must be 1-64")
	}
	servers, err := parseServers(opts.servers, resolversFunc)
	if err != nil {
		_ = out.Flush()
		return 2, err
	}

	results := queryAll(ctx, servers, names, qtype, opts.timeout, opts.retries, opts.parallel, opts.quiet)

	if opts.jsonMode {
		err = report.JSONAll(out, results)
	} else {
		err = report.Table(out, results)
	}
	if ferr := out.Flush(); ferr != nil && err == nil {
		return 2, ferr
	}
	if err != nil {
		return 2, err
	}

	// dig-style footer on the human path with multiple resolvers:
	// disagreeing answers usually mean split horizon or a bad view.
	if !opts.jsonMode && len(servers) > 1 {
		if consistent, why := report.Consistent(results); !consistent {
			fmt.Fprintln(stdout, ";; WARNING: servers disagree:", why)
		}
	}
	return report.ExitCode(results), nil
}
