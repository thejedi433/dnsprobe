package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thejedi433/dnsprobe/internal/dns"
)

// fakeServer is the minimal hermetic resolver used by CLI tests.
type fakeServer struct{ addr string }

func newFake(t *testing.T) *fakeServer {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			m, err := dns.Parse(buf[:n])
			if err != nil || len(m.Questions) == 0 {
				continue
			}
			q := m.Questions[0]
			h := make([]byte, 12)
			binary.BigEndian.PutUint16(h[0:2], m.ID)
			switch q.Name {
			case "ok.example":
				binary.BigEndian.PutUint16(h[2:4], 0x8180)
				binary.BigEndian.PutUint16(h[4:6], 1)
				binary.BigEndian.PutUint16(h[6:8], 1)
				resp := append(h, buf[12:n]...)
				rr := nameBytesT(t, "ok.example")
				var rh [10]byte
				binary.BigEndian.PutUint16(rh[0:2], dns.TypeA)
				binary.BigEndian.PutUint16(rh[2:4], dns.ClassIN)
				binary.BigEndian.PutUint32(rh[4:8], 60)
				binary.BigEndian.PutUint16(rh[8:10], 4)
				resp = append(resp, rr...)
				resp = append(resp, rh[:]...)
				resp = append(resp, 127, 0, 0, 1)
				pc.WriteTo(resp, from)
			case "nxd.example":
				binary.BigEndian.PutUint16(h[2:4], 0x8103)
				binary.BigEndian.PutUint16(h[4:6], 1)
				pc.WriteTo(append(h, buf[12:n]...), from)
			}
		}
	}()
	t.Cleanup(func() { pc.Close() })
	return &fakeServer{addr: pc.LocalAddr().String()}
}

func nameBytesT(t *testing.T, s string) []byte {
	t.Helper()
	b, err := dns.EncodeName(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRunOK(t *testing.T) {
	f := newFake(t)
	var buf bytes.Buffer
	code, err := run(context.Background(),
		[]string{"-servers", f.addr, "-q", "ok.example"}, &buf,
		func() []string { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if code != 0 {
		t.Errorf("exit = %d, want 0\n%s", code, buf.String())
	}
	if !strings.Contains(buf.String(), "127.0.0.1") {
		t.Errorf("output missing answer:\n%s", buf.String())
	}
}

func TestRunNXDOMAINExitWarn(t *testing.T) {
	f := newFake(t)
	var buf bytes.Buffer
	code, err := run(context.Background(),
		[]string{"-servers", f.addr, "-q", "nxd.example"}, &buf,
		func() []string { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
}

func TestRunJSON(t *testing.T) {
	f := newFake(t)
	var buf bytes.Buffer
	code, err := run(context.Background(),
		[]string{"-json", "-servers", f.addr, "-q", "ok.example"}, &buf,
		func() []string { return nil })
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	if !strings.Contains(buf.String(), `"rcode":"NOERROR"`) {
		t.Errorf("json out:\n%s", buf.String())
	}
}

func TestRunUsageErrors(t *testing.T) {
	cases := [][]string{
		{"-badflag"},                           // unknown flag
		{},                                     // no names
		{"-type", "BOGUS", "a.example"},        // unknown type
		{"-retries", "9", "a.example"},         // bad retries
		{"-parallel", "0", "a.example"},        // bad parallel
		{"-servers", "", "a.example"},          // empty server list + nil resolvers
		{"-servers", "bad..name", "a.example"}, // invalid server
	}
	for _, args := range cases {
		var buf bytes.Buffer
		code, err := run(context.Background(), args, &buf, func() []string { return nil })
		if err == nil || code != 2 {
			t.Errorf("run(%v) = (%d, %v), want (2, err)", args, code, err)
		}
	}
}

func TestRunDefaultResolvers(t *testing.T) {
	f := newFake(t)
	var buf bytes.Buffer
	// -servers absent: resolversFunc supplies the fake's address
	code, err := run(context.Background(), []string{"-q", "ok.example"}, &buf,
		func() []string { return []string{f.addr} })
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v", code, err)
	}
}

func TestRunTransportFailureExitCrit(t *testing.T) {
	var buf bytes.Buffer
	// bind then close to get a definitely-closed UDP port on loopback
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
	addr := pc.LocalAddr().String()
	pc.Close()
	code, err := run(context.Background(),
		[]string{"-servers", addr, "-timeout", "100ms", "-retries", "0", "-q", "ok.example"}, &buf,
		func() []string { return nil })
	if err != nil {
		t.Fatal(err) // transport failure is a result, not a run error
	}
	if code != 2 {
		t.Errorf("exit = %d, want 2 (output:\n%s)", code, buf.String())
	}
}

func TestParseServers(t *testing.T) {
	// dedupe/empty-tolerant splitting plus port defaults
	got, err := parseServers("8.8.8.8, ,1.1.1.1:5353", func() []string { return nil })
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"8.8.8.8:53", "1.1.1.1:5353"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("got %v want %v", got, want)
	}
	if _, err := parseServers("", func() []string { return nil }); err == nil {
		t.Error("empty fallback accepted")
	}
}

func TestSystemResolversParsesResolvConf(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	content := "# comment\nnameserver 10.0.0.1\n; another\ntypeserver ignored\nnameserver 10.0.0.2 # trailing\nsearch example\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	got := resolversFrom(path)
	if strings.Join(got, ",") != "10.0.0.1,10.0.0.2" {
		t.Errorf("got %v", got)
	}
	// missing file falls back to a public resolver
	if got := resolversFrom(filepath.Join(dir, "nope")); len(got) != 1 {
		t.Errorf("fallback = %v", got)
	}
}

func TestQueryAllCancellation(t *testing.T) {
	f := newFake(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	results := queryAll(ctx, []string{f.addr}, []string{"ok.example"}, dns.TypeA, time.Second, 0, 4, true)
	if len(results) != 1 {
		t.Fatalf("len = %d", len(results))
	}
	if results[0].Err == "" && results[0].Answered {
		t.Error("cancelled context should not produce a clean answered result")
	}
}

func TestQueryAllProgressPath(t *testing.T) {
	f := newFake(t)
	// quiet=false exercises the stderr progress lines (both branches)
	results := queryAll(context.Background(),
		[]string{f.addr}, []string{"ok.example", "nxd.example"}, dns.TypeA,
		2*time.Second, 0, 4, false)
	if len(results) != 2 {
		t.Fatalf("len = %d", len(results))
	}
}

func TestSystemResolversReal(t *testing.T) {
	// whatever the host has, we must get at least one usable address
	out := systemResolvers()
	if len(out) == 0 {
		t.Fatal("no resolvers")
	}
}

// conflictServer answers "conflict.example" with the given rcode number.
func conflictServer(t *testing.T, rcode uint16) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 512)
		n, from, err := pc.ReadFrom(buf)
		if err != nil || n < 12 {
			return
		}
		resp := make([]byte, 12)
		binary.BigEndian.PutUint16(resp[0:2], binary.BigEndian.Uint16(buf[0:2]))
		binary.BigEndian.PutUint16(resp[2:4], 0x8100|rcode)
		binary.BigEndian.PutUint16(resp[4:6], 1)
		pc.WriteTo(append(resp, buf[12:n]...), from)
	}()
	return pc.LocalAddr().String()
}

func TestRunServersDisagreeFooter(t *testing.T) {
	a := conflictServer(t, 0) // NOERROR
	b := conflictServer(t, 2) // SERVFAIL
	var buf bytes.Buffer
	code, err := run(context.Background(),
		[]string{"-servers", a + "," + b, "-q", "conflict.example"}, &buf,
		func() []string { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
	if !strings.Contains(buf.String(), "WARNING: servers disagree") {
		t.Errorf("missing disagreement footer:\n%s", buf.String())
	}
}
