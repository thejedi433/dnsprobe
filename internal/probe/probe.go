// Package probe sends DNS queries over UDP (with TCP fallback on
// truncation) and collects per-server timings. Pure Go stdlib.
package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/thejedi433/dnsprobe/internal/dns"
)

// Result is the outcome of one query against one resolver.
type Result struct {
	Server    string        `json:"server"`
	Name      string        `json:"name"`
	Type      string        `json:"type"`
	RTT       time.Duration `json:"rtt_ns,omitzero"`
	Rcode     string        `json:"rcode,omitempty"`
	Answered  bool          `json:"answered"` // got a parseable response
	Truncated bool          `json:"truncated"`
	Answers   []dns.Record  `json:"answers,omitempty"`
	Err       string        `json:"error,omitempty"`
	ProbeAt   time.Time     `json:"probe_at,omitzero"`
	TCPRetry  bool          `json:"tcp_retry"` // needed TCP fallback
}

// OK reports whether the query returned a parseable response with
// NOERROR (answers may legitimately be empty for e.g. A on a CNAME-only
// name, so NOERROR with no answers is still OK).
func (r Result) OK() bool {
	return r.Answered && r.Err == "" && r.Rcode == "NOERROR"
}

// ServerSpec is a resolver address plus optional port (default 53).
func ParseServer(s string) (string, error) {
	if s == "" {
		return "", errors.New("empty server")
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		// no port given: accept bare IP or hostname
		ip := net.ParseIP(s)
		if ip == nil && !validHostname(s) {
			return "", fmt.Errorf("invalid server %q", s)
		}
		return net.JoinHostPort(s, "53"), nil
	}
	if host == "" {
		return "", fmt.Errorf("invalid server %q", s)
	}
	p, err := net.LookupPort("udp", port)
	if err != nil || p <= 0 || p > 65535 {
		return "", fmt.Errorf("invalid port in server %q", s)
	}
	return net.JoinHostPort(host, fmt.Sprint(p)), nil
}

func validHostname(s string) bool {
	_, err := dns.EncodeName(s)
	return err == nil
}

// Query sends one query for name/qtype to server and returns the result.
// The caller-supplied context bounds the whole exchange including the
// optional TCP retry.
func Query(ctx context.Context, server, name string, qtype uint16, timeout time.Duration) Result {
	res := Result{Server: server, Name: name, Type: dns.TypeName(qtype), ProbeAt: time.Now().UTC()}
	msg, err := dns.BuildQuery(queryID(), name, qtype)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	start := time.Now()
	resp, err := exchangeUDP(ctx, server, msg, timeout)
	res.RTT = time.Since(start)
	if ctx.Err() != nil {
		res.Err = "context cancelled"
		return res
	}
	if err != nil {
		res.Err = err.Error()
		return res
	}
	m, err := dns.Parse(resp)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	if m.ID != binary.BigEndian.Uint16(msg[0:2]) {
		res.Err = "response id mismatch"
		return res
	}
	res.Answered = true
	res.Rcode = dns.RcodeName(m.Rcode)
	if m.TC { // truncated: retry over TCP per RFC 5966 / RFC 1035 4.2.1
		res.Truncated = true
		res.TCPRetry = true
		start = time.Now()
		resp, err = exchangeTCP(ctx, server, msg, timeout)
		res.RTT += time.Since(start)
		if err != nil {
			res.Err = "tcp retry: " + err.Error()
			return res
		}
		m, err = dns.Parse(resp)
		if err != nil {
			res.Err = "tcp retry: " + err.Error()
			return res
		}
	}
	res.Answers = m.Answers
	return res
}

func queryID() uint16 {
	// A fixed ID invites trivial spoofing; UnixNano-based low bits are
	// enough for a diagnostic tool (crypto/rand would be overkill here).
	return uint16(time.Now().UnixNano())
}

func exchangeUDP(ctx context.Context, server string, msg []byte, timeout time.Duration) ([]byte, error) {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "udp", server)
	if err != nil {
		return nil, err
	}
	uc, ok := conn.(*net.UDPConn)
	if !ok {
		conn.Close()
		return nil, errors.New("not a udp conn")
	}
	defer uc.Close()
	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	uc.SetDeadline(deadline)
	if _, err := uc.Write(msg); err != nil {
		return nil, err
	}
	buf := make([]byte, 512) // classic UDP DNS payload ceiling
	n, err := uc.Read(buf)
	if err != nil {
		return nil, err
	}
	if n < 12 {
		return nil, fmt.Errorf("%w: short udp response (%d bytes)", dns.ErrMalformed, n)
	}
	return buf[:n], nil
}

func exchangeTCP(ctx context.Context, server string, msg []byte, timeout time.Duration) ([]byte, error) {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	conn.SetDeadline(deadline)
	var lenbuf [2]byte
	binary.BigEndian.PutUint16(lenbuf[:], uint16(len(msg)))
	if _, err := conn.Write(append(lenbuf[:], msg...)); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(conn, lenbuf[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint16(lenbuf[:])
	if n < 12 {
		return nil, fmt.Errorf("%w: short tcp response (%d bytes)", dns.ErrMalformed, n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}
