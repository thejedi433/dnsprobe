package probe

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/thejedi433/dnsprobe/internal/dns"
)

// fakeResolver answers queries on a local UDP socket: "ok.example" gets
// NOERROR + one A record, "nxd.example" gets NXDOMAIN, "empty.example"
// gets NOERROR with no answers, "trunc.example" gets TC=1 over UDP and a
// full answer over TCP, "garbage.example" answers a malformed message.
// "slow.example" never answers (for timeout/retry tests).
func fakeResolver(t *testing.T) (addr string, tcpAddr string) {
	t.Helper()
	tcpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// real resolvers answer UDP and TCP on the same port; mirror that
	_, port, err := net.SplitHostPort(tcpLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	udpConn, err := net.ListenPacket("udp", "127.0.0.1:"+port)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 1024)
		for {
			n, from, err := udpConn.ReadFrom(buf)
			if err != nil {
				return // listener closed
			}
			resp := answer(t, buf[:n], false)
			if resp == nil {
				continue
			}
			udpConn.WriteTo(resp, from)
		}
	}()
	go func() {
		for {
			c, err := tcpLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				var lenbuf [2]byte
				if _, err := c.Read(lenbuf[:]); err != nil {
					return
				}
				n := int(binary.BigEndian.Uint16(lenbuf[:]))
				msg := make([]byte, n)
				if _, err := c.Read(msg); err != nil {
					return
				}
				resp := answer(t, msg, true)
				if resp == nil {
					return
				}
				binary.BigEndian.PutUint16(lenbuf[:], uint16(len(resp)))
				c.Write(lenbuf[:])
				c.Write(resp)
			}()
		}
	}()
	t.Cleanup(func() {
		udpConn.Close()
		tcpLn.Close()
	})
	return udpConn.LocalAddr().String(), tcpLn.Addr().String()
}

func answer(t *testing.T, msg []byte, tcp bool) []byte {
	t.Helper()
	m, err := dns.Parse(msg)
	if err != nil || len(m.Questions) == 0 {
		return nil
	}
	q := m.Questions[0]
	id := m.ID
	// responses must echo the question section (RFC 1035 3.2.3)
	qsec := msg[12:]

	switch q.Name {
	case "slow.example":
		return nil // silence
	case "garbage.example":
		return []byte{1, 2, 3} // short garbage
	case "trunc.example":
		if !tcp { // over UDP, claim truncation with just header+question
			h := make([]byte, 12)
			binary.BigEndian.PutUint16(h[0:2], id)
			binary.BigEndian.PutUint16(h[2:4], 0x8380) // QR|RD|TC, NOERROR
			binary.BigEndian.PutUint16(h[4:6], 1)
			return append(h, qsec...)
		}
		// over TCP: real answer
		return buildAnswer(t, id, q.Name, 44)
	case "ok.example", "www.example":
		return buildAnswer(t, id, q.Name, 0)
	case "nxd.example":
		h := make([]byte, 12)
		binary.BigEndian.PutUint16(h[0:2], id)
		binary.BigEndian.PutUint16(h[2:4], uint16(0x8100)|3) // QR|RD + NXDOMAIN
		binary.BigEndian.PutUint16(h[4:6], 1)
		return append(h, qsec...)
	case "empty.example":
		h := make([]byte, 12)
		binary.BigEndian.PutUint16(h[0:2], id)
		binary.BigEndian.PutUint16(h[2:4], 0x8180)
		binary.BigEndian.PutUint16(h[4:6], 1)
		return append(h, qsec...)
	}
	return nil
}

// buildAnswer returns a response with one A record; extraTTL>0 exercises
// value variation between servers.
func buildAnswer(t *testing.T, id uint16, name string, ttl uint32) []byte {
	t.Helper()
	h := make([]byte, 12)
	binary.BigEndian.PutUint16(h[0:2], id)
	binary.BigEndian.PutUint16(h[2:4], 0x8180)
	binary.BigEndian.PutUint16(h[4:6], 1)
	binary.BigEndian.PutUint16(h[6:8], 1)
	qn, err := dns.EncodeName(name)
	if err != nil {
		t.Fatal(err)
	}
	h = append(h, qn...)
	h = append(h, 0, dns.TypeA, 0, dns.ClassIN)
	h = append(h, qn...) // the answer record's NAME (RFC 1035 3.2.1)
	var rr [10]byte
	binary.BigEndian.PutUint16(rr[0:2], dns.TypeA)
	binary.BigEndian.PutUint16(rr[2:4], dns.ClassIN)
	binary.BigEndian.PutUint32(rr[4:8], ttl)
	binary.BigEndian.PutUint16(rr[8:10], 4)
	h = append(h, rr[:]...)
	h = append(h, 127, 0, 0, 1)
	return h
}

func TestQueryOK(t *testing.T) {
	addr, _ := fakeResolver(t)
	r := Query(context.Background(), addr, "ok.example", dns.TypeA, 2*time.Second)
	if !r.OK() {
		t.Fatalf("result not OK: %+v", r)
	}
	if len(r.Answers) != 1 || r.Answers[0].Data != "127.0.0.1" {
		t.Fatalf("answers: %+v", r.Answers)
	}
	if r.RTT <= 0 {
		t.Error("rtt not measured")
	}
}

func TestQueryNXDOMAIN(t *testing.T) {
	addr, _ := fakeResolver(t)
	r := Query(context.Background(), addr, "nxd.example", dns.TypeA, 2*time.Second)
	if r.Err != "" || !r.Answered {
		t.Fatalf("want answered, got %+v", r)
	}
	if r.Rcode != "NXDOMAIN" {
		t.Errorf("rcode = %q, want NXDOMAIN", r.Rcode)
	}
}

func TestQueryEmptyAnswerIsOK(t *testing.T) {
	addr, _ := fakeResolver(t)
	r := Query(context.Background(), addr, "empty.example", dns.TypeA, 2*time.Second)
	if !r.OK() {
		t.Errorf("NOERROR with 0 answers should be OK: %+v", r)
	}
	if len(r.Answers) != 0 {
		t.Errorf("answers = %d, want 0", len(r.Answers))
	}
}

func TestQueryTruncatedTCPRetry(t *testing.T) {
	addr, _ := fakeResolver(t)
	r := Query(context.Background(), addr, "trunc.example", dns.TypeA, 2*time.Second)
	if r.Err != "" {
		t.Fatalf("err: %v", r.Err)
	}
	if !r.Truncated || !r.TCPRetry {
		t.Fatalf("expected trunc+retry flags: %+v", r)
	}
	if len(r.Answers) != 1 {
		t.Fatalf("answers after TCP retry: %+v", r.Answers)
	}
}

func TestQueryGarbageParseError(t *testing.T) {
	addr, _ := fakeResolver(t)
	r := Query(context.Background(), addr, "garbage.example", dns.TypeA, 2*time.Second)
	if r.Err == "" || r.Answered {
		t.Fatalf("want parse error, got %+v", r)
	}
	if !strings.Contains(r.Err, "malformed") {
		t.Errorf("err = %q, want malformed mention", r.Err)
	}
}

func TestQueryTimeout(t *testing.T) {
	addr, _ := fakeResolver(t)
	start := time.Now()
	r := Query(context.Background(), addr, "slow.example", dns.TypeA, 150*time.Millisecond)
	if r.Err == "" {
		t.Fatalf("want timeout error, got %+v", r)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Errorf("timeout not honored: %v", el)
	}
}

func TestQueryCancelledContext(t *testing.T) {
	addr, _ := fakeResolver(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := Query(ctx, addr, "ok.example", dns.TypeA, time.Second)
	if r.Err == "" {
		t.Fatalf("want cancelled, got %+v", r)
	}
}

func TestQueryUnreachableServer(t *testing.T) {
	// port 0-ish closed port on loopback: dial succeeds (UDP), but no
	// answer ever comes; use a bound-then-closed socket address instead.
	addr, _ := fakeResolver(t)
	// rebind trick: ask a valid but silent addr with tiny timeout
	r := Query(context.Background(), addr, "nonexistent-name", dns.TypeA, 100*time.Millisecond)
	if r.Err == "" {
		t.Fatalf("want error for unanswered query, got %+v", r)
	}
}

func TestParseServer(t *testing.T) {
	cases := []struct {
		in   string
		want string
		bad  bool
	}{
		{"8.8.8.8", "8.8.8.8:53", false},
		{"8.8.8.8:5353", "8.8.8.8:5353", false},
		{"2001:db8::1", "[2001:db8::1]:53", false},
		{"2001:db8::1:53", "[2001:db8::1:53]:53", false}, // parsed as IPv6, colon not a port sep for bare v6
		{"[::1]:5300", "[::1]:5300", false},
		{"resolver.example", "resolver.example:53", false},
		{"", "", true},
		{":53", "", true},
		{"8.8.8.8:abc", "", true},
		{"8.8.8.8:0", "", true},
		{"8.8.8.8:99999", "", true},
		{"bad..name", "", true},
	}
	for _, c := range cases {
		got, err := ParseServer(c.in)
		if c.bad {
			if err == nil {
				t.Errorf("ParseServer(%q) accepted: %q", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseServer(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseServer(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestResultOKFields(t *testing.T) {
	r := Query(context.Background(), "127.0.0.1:1", "ok.example", dns.TypeA, 100*time.Millisecond)
	if r.OK() {
		t.Error("errored result reports OK")
	}
	if r.ProbeAt.IsZero() {
		t.Error("ProbeAt not set")
	}
	if r.Type != "A" {
		t.Errorf("Type = %q", r.Type)
	}
}

func TestQueryBuildError(t *testing.T) {
	addr, _ := fakeResolver(t)
	r := Query(context.Background(), addr, "bad..name", dns.TypeA, time.Second)
	if r.Err == "" || strings.Contains(r.Err, "malformed dns message: empty label") == false {
		t.Fatalf("want encode error, got %+v", r)
	}
}

func TestQueryIDMismatch(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 512)
		n, from, _ := pc.ReadFrom(buf)
		if n < 12 {
			return
		}
		resp := make([]byte, 12)
		binary.BigEndian.PutUint16(resp[0:2], 0x9999) // wrong ID
		binary.BigEndian.PutUint16(resp[2:4], 0x8180)
		binary.BigEndian.PutUint16(resp[4:6], 1)
		resp = append(resp, buf[12:n]...)
		pc.WriteTo(resp, from)
	}()
	r := Query(context.Background(), pc.LocalAddr().String(), "x.example", dns.TypeA, time.Second)
	if r.Err != "response id mismatch" {
		t.Errorf("err = %q, want id mismatch", r.Err)
	}
}

func TestQueryTCPRetryRefused(t *testing.T) {
	// UDP server answers trunc.example with TC=1 but no TCP listener
	// exists on that port -> tcp retry dial fails.
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			resp := make([]byte, 12)
			binary.BigEndian.PutUint16(resp[0:2], binary.BigEndian.Uint16(buf[0:2]))
			binary.BigEndian.PutUint16(resp[2:4], 0x8380) // TC
			binary.BigEndian.PutUint16(resp[4:6], 1)
			resp = append(resp, buf[12:n]...)
			pc.WriteTo(resp, from)
		}
	}()
	addr := pc.LocalAddr().String()
	h, p, _ := net.SplitHostPort(addr)
	_ = p
	// The TCP port equals the UDP one only by convention here; ensure it
	// is closed by never opening one.
	_ = h
	r := Query(context.Background(), addr, "trunc.example", dns.TypeA, 500*time.Millisecond)
	if !strings.HasPrefix(r.Err, "tcp retry:") || !r.Truncated || !r.TCPRetry {
		t.Fatalf("want tcp retry failure, got %+v", r)
	}
}

func TestQueryTCPRetryGarbage(t *testing.T) {
	lst, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lst.Close()
	go func() {
		c, err := lst.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		var lb [2]byte
		c.Read(lb[:])
		n := int(binary.BigEndian.Uint16(lb[:]))
		c.Read(make([]byte, n))
		resp := []byte{0, 5} // claims 5 bytes -> below 12 -> malformed
		c.Write(resp)
	}()
	_, port, _ := net.SplitHostPort(lst.Addr().String())
	udpAddr := "127.0.0.1:" + port
	// UDP half answering TC=1:
	pc, err := net.ListenPacket("udp", udpAddr)
	if err != nil {
		t.Fatal(err) // port must be free for the tcp listener we already hold
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			resp := make([]byte, 12)
			binary.BigEndian.PutUint16(resp[0:2], binary.BigEndian.Uint16(buf[0:2]))
			binary.BigEndian.PutUint16(resp[2:4], 0x8380)
			binary.BigEndian.PutUint16(resp[4:6], 1)
			resp = append(resp, buf[12:n]...)
			pc.WriteTo(resp, from)
		}
	}()
	r := Query(context.Background(), udpAddr, "trunc.example", dns.TypeA, 2*time.Second)
	if !strings.HasPrefix(r.Err, "tcp retry: malformed") {
		t.Fatalf("want tcp parse error, got %+v", r)
	}
}

func TestQueryUsesContextDeadlineClamp(t *testing.T) {
	// ctx deadline SHORTER than -timeout must win: slow.example would
	// otherwise run the full 30s timeout.
	addr, _ := fakeResolver(t)
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	r := Query(ctx, addr, "slow.example", dns.TypeA, 30*time.Second)
	el := time.Since(start)
	if r.Err == "" {
		t.Fatalf("want deadline error, got %+v", r)
	}
	if el > 5*time.Second {
		t.Errorf("ctx deadline ignored: %v", el)
	}
}
