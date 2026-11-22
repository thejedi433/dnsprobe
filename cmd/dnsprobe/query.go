package main

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/thejedi433/dnsprobe/internal/dns"
	"github.com/thejedi433/dnsprobe/internal/probe"
)

// queryAll runs every (server, name) pair with bounded parallelism.
// Progress goes to stderr (one line per name, dig-style) unless quiet.
func queryAll(ctx context.Context, servers []string, names []string, qtype uint16, timeout time.Duration, retries, parallel int, quiet bool) []probe.Result {
	type job struct {
		server string
		name   string
		idx    int
	}
	total := len(servers) * len(names)
	jobs := make(chan job, total)
	results := make([]probe.Result, total)
	for i, s := range servers {
		for j, n := range names {
			jobs <- job{server: s, name: n, idx: i*len(names) + j}
		}
	}
	close(jobs)

	seen := make(map[string]bool)
	var seenMu sync.Mutex
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup
	for range total {
		wg.Add(1)
		go func() {
			defer wg.Done()
			j := <-jobs
			sem <- struct{}{}
			defer func() { <-sem }()
			r := queryWithRetry(ctx, j.server, j.name, qtype, timeout, retries)
			results[j.idx] = r
			if !quiet {
				seenMu.Lock()
				first := !seen[j.name]
				seen[j.name] = true
				seenMu.Unlock()
				if first {
					if r.Answered && r.Err == "" {
						fmt.Fprintf(os.Stderr, "%s %s %s\n", j.name, dns.TypeName(qtype), r.Rcode)
					} else {
						fmt.Fprintf(os.Stderr, "%s %s ERROR (%s)\n", j.name, dns.TypeName(qtype), j.server)
					}
				}
			}
		}()
	}
	wg.Wait()
	return results
}

// queryWithRetry repeats Query while it fails at the transport/parse
// level (Err set, not answered). Answered errors (rcode mismatch etc.)
// are returned immediately; a name is authoritative even if odd.
func queryWithRetry(ctx context.Context, server, name string, qtype uint16, timeout time.Duration, retries int) probe.Result {
	var r probe.Result
	for attempt := 0; attempt <= retries; attempt++ {
		if ctx.Err() != nil {
			r = probe.Result{Server: server, Name: name, Type: dns.TypeName(qtype), Err: "cancelled before attempt"}
			return r
		}
		r = probe.Query(ctx, server, name, qtype, timeout)
		if r.Err == "" {
			return r
		}
	}
	return r
}
