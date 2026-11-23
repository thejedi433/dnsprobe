package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/thejedi433/dnsprobe/internal/dns"
	"github.com/thejedi433/dnsprobe/internal/probe"
)

func rec(name, server, rcode, data string, ttl uint32) probe.Result {
	return probe.Result{
		Server: server, Name: name, Type: "A", Answered: rcode != "",
		Rcode: rcode, RTT: 5 * time.Millisecond,
		Answers: []dns.Record{{Name: name, Type: dns.TypeA, TTL: ttl, Data: data}},
	}
}

func TestExitCode(t *testing.T) {
	ok := rec("a.example", "1.1.1.1:53", "NOERROR", "1.2.3.4", 60)
	nx := rec("b.example", "1.1.1.1:53", "NXDOMAIN", "", 0)
	dead := probe.Result{Server: "9.9.9.9:53", Name: "c.example", Err: "i/o timeout"}

	if got := ExitCode([]probe.Result{ok}); got != ExitOK {
		t.Errorf("all ok = %d", got)
	}
	if got := ExitCode([]probe.Result{ok, nx}); got != ExitWarn {
		t.Errorf("nx = %d, want 1", got)
	}
	if got := ExitCode([]probe.Result{ok, dead}); got != ExitCrit {
		t.Errorf("dead = %d, want 2", got)
	}
	unanswered := probe.Result{Server: "x", Answered: false}
	if got := ExitCode([]probe.Result{unanswered}); got != ExitCrit {
		t.Errorf("unanswered = %d, want 2", got)
	}
}

func TestConsistent(t *testing.T) {
	a := rec("a.example", "1.1.1.1:53", "NOERROR", "1.2.3.4", 60)
	b := rec("a.example", "8.8.8.8:53", "NOERROR", "5.6.7.8", 30) // different value, same rcode
	if ok, why := Consistent([]probe.Result{a, b}); !ok {
		t.Errorf("round-robin values flagged: %s", why)
	}
	nx := rec("a.example", "8.8.8.8:53", "NXDOMAIN", "", 0)
	if ok, why := Consistent([]probe.Result{a, nx}); ok {
		t.Error("rcode disagreement missed")
	} else if !strings.Contains(why, "NXDOMAIN") {
		t.Errorf("why = %q", why)
	}
	// multi-name: consistent for name1, inconsistent for name2
	n1a := rec("n1.example", "1.1.1.1:53", "NOERROR", "1", 60)
	n1b := rec("n1.example", "8.8.8.8:53", "NOERROR", "2", 60)
	n2b := rec("n2.example", "8.8.8.8:53", "SERVFAIL", "", 0)
	n2a := rec("n2.example", "1.1.1.1:53", "NOERROR", "3", 60)
	ok, why := Consistent([]probe.Result{n1a, n1b, n2a, n2b})
	if ok || !strings.Contains(why, "n2.example") {
		t.Errorf("multi-name: ok=%v why=%q", ok, why)
	}
	// errors are skipped in comparison
	dead := probe.Result{Server: "9.9.9.9:53", Name: "a.example", Err: "timeout"}
	if ok, _ := Consistent([]probe.Result{a, dead}); !ok {
		t.Error("errored result should not affect consistency")
	}
	// empty set
	if ok, why := Consistent(nil); !ok || why != "" {
		t.Error("empty should be consistent")
	}
}

func TestTableRenders(t *testing.T) {
	var buf bytes.Buffer
	results := []probe.Result{
		rec("a.example", "1.1.1.1:53", "NOERROR", "1.2.3.4", 60),
		rec("b.example", "8.8.8.8:53", "NXDOMAIN", "", 0),
		{Server: "9.9.9.9:53", Name: "c.example", Err: "i/o timeout"},
		{Server: "4.4.4.4:53", Name: "d.example", Type: "TXT", Answered: true, Rcode: "NOERROR"},
	}
	// b.example must be answered but with empty answers; rec adds one answer, adjust
	results[1].Answers = nil
	results[3].Answers = nil
	if err := Table(&buf, results); err != nil {
		t.Fatal(err)
	}
	s := buf.String()
	for _, want := range []string{
		";; SERVER: 1.1.1.1:53 (NOERROR)",
		"a.example", "1.2.3.4",
		"(NXDOMAIN)",
		";; i/o timeout",
		";; 0 answers",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
}

func TestTableTruncatedNote(t *testing.T) {
	var buf bytes.Buffer
	r := rec("a.example", "1.1.1.1:53", "NOERROR", "1.2.3.4", 60)
	r.Truncated = true
	Table(&buf, []probe.Result{r})
	if !strings.Contains(buf.String(), "truncated over UDP") {
		t.Errorf("missing truncation note:\n%s", buf.String())
	}
}

type failWriter struct{ n int }

func (f *failWriter) Write(p []byte) (int, error) {
	f.n++
	if f.n > 1 {
		return 0, errors.New("boom")
	}
	return len(p), nil
}

// failAtWriter fails every write after the first failAfter calls.
type failAtWriter struct{ ok int }

func (f *failAtWriter) Write(p []byte) (int, error) {
	if f.ok > 0 {
		f.ok--
		return len(p), nil
	}
	return 0, errors.New("boom")
}

func TestTableWriteError(t *testing.T) {
	results := []probe.Result{
		rec("a.example", "1.1.1.1:53", "NOERROR", "1.2.3.4", 60),
		rec("b.example", "8.8.8.8:53", "NOERROR", "5.6.7.8", 60),
	}
	if err := Table(&failWriter{}, results); err == nil {
		t.Error("write error not propagated")
	}
	// header-line failure (first write errors)
	if err := Table(&failAtWriter{}, results); err == nil {
		t.Error("header write error not propagated")
	}
	// error-note line failure (second write errors, Err set)
	bad := probe.Result{Server: "9.9.9.9:53", Name: "x.example", Err: "i/o timeout"}
	if err := Table(&failAtWriter{ok: 1}, []probe.Result{bad}); err == nil {
		t.Error("error-note write failure not propagated")
	}
	// truncated-note line failure (second write errors, Truncated set)
	tr := rec("a.example", "1.1.1.1:53", "NOERROR", "1.2.3.4", 60)
	tr.Truncated = true
	if err := Table(&failAtWriter{ok: 1}, []probe.Result{tr}); err == nil {
		t.Error("truncated-note write failure not propagated")
	}
	// 0-answers note failure (second write errors, no answer rows)
	empty := probe.Result{Server: "1.1.1.1:53", Name: "a.example", Type: "A", Answered: true, Rcode: "NOERROR"}
	if err := Table(&failAtWriter{ok: 1}, []probe.Result{empty}); err == nil {
		t.Error("0-answers write failure not propagated")
	}
}

func TestJSONAll(t *testing.T) {
	var buf bytes.Buffer
	results := []probe.Result{rec("a.example", "1.1.1.1:53", "NOERROR", "1.2.3.4", 60)}
	if err := JSONAll(&buf, results); err != nil {
		t.Fatal(err)
	}
	var back []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatal(err)
	}
	if back[0]["server"] != "1.1.1.1:53" || back[0]["rcode"] != "NOERROR" {
		t.Errorf("json roundtrip: %v", back[0])
	}
}

func TestJSONWriteError(t *testing.T) {
	if err := JSONAll(&failWriter2{}, []probe.Result{{Server: "x"}}); err == nil {
		t.Error("expected write error")
	}
}

type failWriter2 struct{}

func (failWriter2) Write(p []byte) (int, error) { return 0, io.ErrClosedPipe }

func TestTableUnicodePadding(t *testing.T) {
	// a TXT record with multi-byte chars must not crash width math
	var buf bytes.Buffer
	r := probe.Result{
		Server: "1.1.1.1:53", Name: "a.example", Answered: true, Rcode: "NOERROR",
		Answers: []dns.Record{{Name: "a.example", Type: dns.TypeTXT, Data: `"日本語テキスト"`}},
	}
	if err := Table(&buf, []probe.Result{r}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "日本語") {
		t.Errorf("unicode content lost: %s", buf.String())
	}
}
