package main

import (
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/thejedi433/dnsprobe/internal/probe"
)

type options struct {
	typeName string
	servers  string
	timeout  time.Duration
	retries  int
	parallel int
	jsonMode bool
	quiet    bool
}

func newFlagSet(out io.Writer) (*flag.FlagSet, *options) {
	fs := flag.NewFlagSet("dnsprobe", flag.ContinueOnError)
	fs.SetOutput(out)
	o := &options{}
	fs.StringVar(&o.typeName, "type", "A", "record type: A, AAAA, CNAME, MX, NS, PTR, SOA, TXT")
	fs.StringVar(&o.servers, "servers", "", "comma-separated resolver IPs (default: system resolvers)")
	fs.DurationVar(&o.timeout, "timeout", 5*time.Second, "per-query timeout")
	fs.DurationVar(&o.timeout, "t", 5*time.Second, "shorthand for -timeout")
	fs.IntVar(&o.retries, "retries", 2, "retry count on timeout/IO error (0-5)")
	fs.IntVar(&o.parallel, "parallel", 8, "concurrent queries (1-64)")
	fs.BoolVar(&o.jsonMode, "json", false, "JSON output")
	fs.BoolVar(&o.quiet, "q", false, "suppress the per-name progress line on stderr")
	return fs, o
}

// parseServers resolves the -servers flag into a usable list, falling
// back to resolversFunc (system resolvers) when the flag is empty.
func parseServers(list string, resolversFunc func() []string) ([]string, error) {
	var raw []string
	if list != "" {
		for _, s := range strings.Split(list, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				raw = append(raw, s)
			}
		}
	} else {
		raw = resolversFunc()
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("no resolvers available (specify -servers)")
	}
	out := make([]string, 0, len(raw))
	for _, s := range raw {
		addr, err := probe.ParseServer(s)
		if err != nil {
			return nil, err
		}
		out = append(out, addr)
	}
	return out, nil
}
