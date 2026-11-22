// Package report renders probe results as a dig-style table or JSON and
// computes the process exit code.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/thejedi433/dnsprobe/internal/dns"
	"github.com/thejedi433/dnsprobe/internal/probe"
)

// Exit codes: 0 all servers answered NOERROR, 1 at least one answered
// with an error rcode (SERVFAIL/REFUSED/NXDOMAIN are surfaced there),
// 2 transport or parse failure somewhere.
const (
	ExitOK   = 0
	ExitWarn = 1
	ExitCrit = 2
)

// ExitCode derives the process status from results. Any non-NOERROR
// rcode counts as a warning (exit 1): SERVFAIL and REFUSED mean a
// broken resolver, NXDOMAIN usually means a broken expectation too.
func ExitCode(results []probe.Result) int {
	code := ExitOK
	for _, r := range results {
		if r.Err != "" || !r.Answered {
			return ExitCrit
		}
		if r.Rcode != "NOERROR" {
			code = ExitWarn
		}
	}
	return code
}

// Consistent reports whether, for every queried name, all answering
// servers agree on the rcode. Record *values* routinely differ across
// public resolvers (round-robin, ECS-based views), so comparing them
// would flag noise; a differing rcode (one server says NXDOMAIN,
// another NOERROR) is a genuine view/split-horizon fault signal.
func Consistent(results []probe.Result) (bool, string) {
	byName := make(map[string][]probe.Result)
	var order []string
	for _, r := range results {
		if !r.Answered {
			continue
		}
		if _, ok := byName[r.Name]; !ok {
			order = append(order, r.Name)
		}
		byName[r.Name] = append(byName[r.Name], r)
	}
	for _, name := range order {
		ref := byName[name][0]
		for _, r := range byName[name][1:] {
			if r.Rcode != ref.Rcode {
				return false, fmt.Sprintf("%s: %s (%s) vs %s (%s)",
					name, ref.Server, ref.Rcode, r.Server, r.Rcode)
			}
		}
	}
	return true, ""
}

// Table renders one dig-style block per server.
func Table(w io.Writer, results []probe.Result) error {
	for _, r := range results {
		status := "NOERROR"
		if r.Err != "" {
			status = "ERROR"
		} else if r.Rcode != "" {
			status = r.Rcode
		}
		line := fmt.Sprintf(";; SERVER: %s (%s) - rtt %s",
			r.Server, status, r.RTT.Round(time.Microsecond))
		if r.Type != "" {
			line += fmt.Sprintf(" - %s", r.Type)
		}
		if err := writeln(w, line); err != nil {
			return err
		}
		if r.Err != "" {
			if err := writeln(w, ";; "+r.Err); err != nil {
				return err
			}
			continue
		}
		if r.Truncated {
			if err := writeln(w, ";; truncated over UDP; retried over TCP"); err != nil {
				return err
			}
		}
		widths := columnWidths(r)
		for _, a := range r.Answers {
			cols := []string{a.Name, dns.TypeName(a.Type), fmt.Sprint(a.TTL), a.Data}
			var sb strings.Builder
			for i, c := range cols {
				pad := widths[i] - utf8.RuneCountInString(c)
				if pad < 0 {
					pad = 0
				}
				sb.WriteString(c)
				sb.WriteString(strings.Repeat(" ", pad))
				sb.WriteString(" ")
			}
			if err := writeln(w, strings.TrimRight(sb.String(), " ")); err != nil {
				return err
			}
		}
		if len(r.Answers) == 0 {
			if err := writeln(w, ";; 0 answers"); err != nil {
				return err
			}
		}
	}
	return nil
}

func columnWidths(r probe.Result) [4]int {
	var w [4]int
	head := [4]string{"NAME", "TYPE", "TTL", "DATA"}
	for i, h := range head {
		w[i] = utf8.RuneCountInString(h)
	}
	for _, a := range r.Answers {
		cols := []string{a.Name, dns.TypeName(a.Type), fmt.Sprint(a.TTL), a.Data}
		for i, c := range cols {
			if n := utf8.RuneCountInString(c); n > w[i] {
				w[i] = n
			}
		}
	}
	return w
}

func writeln(w io.Writer, s string) error {
	_, err := fmt.Fprintln(w, s)
	return err
}

// JSONAll renders the full result set as a JSON array.
func JSONAll(w io.Writer, results []probe.Result) error {
	return json.NewEncoder(w).Encode(results)
}
