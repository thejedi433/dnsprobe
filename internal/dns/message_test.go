package dns

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestEncodeName(t *testing.T) {
	cases := []struct {
		in   string
		want []byte
	}{
		{"", []byte{0}},
		{".", []byte{0}},
		{"example.com", []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}},
		{"EXAMPLE.COM.", []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}},
	}
	for _, c := range cases {
		got, err := EncodeName(c.in)
		if err != nil {
			t.Fatalf("EncodeName(%q): %v", c.in, err)
		}
		if !bytes.Equal(got, c.want) {
			t.Errorf("EncodeName(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestEncodeNameErrors(t *testing.T) {
	if _, err := EncodeName("a..b"); err == nil {
		t.Error("empty label accepted")
	}
	long := strings.Repeat("x", 64)
	if _, err := EncodeName(long + ".com"); err == nil {
		t.Error("over-long label accepted")
	}
	// BuildQuery must surface EncodeName errors (covers its error branch)
	if _, err := BuildQuery(1, "a..b", TypeA); err == nil {
		t.Error("BuildQuery accepted invalid name")
	}
	if _, err := BuildQuery(1, long+".com", TypeA); err == nil {
		t.Error("BuildQuery accepted over-long name")
	}
	// total wire length > 255: pack as many 63-byte labels as fit
	var parts []string
	for i := 0; i < 6; i++ {
		parts = append(parts, strings.Repeat("y", 63))
	}
	if _, err := EncodeName(strings.Join(parts, ".") + ".com"); err == nil {
		t.Error("over-long name accepted")
	}
}

func TestBuildQuery(t *testing.T) {
	msg, err := BuildQuery(0x1234, "example.com", TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if len(msg) != 29 { // 12 hdr + 13 name + 4 qtr
		t.Fatalf("len = %d, want 29", len(msg))
	}
	if id := binary.BigEndian.Uint16(msg[0:2]); id != 0x1234 {
		t.Errorf("id = %x", id)
	}
	if flags := binary.BigEndian.Uint16(msg[2:4]); flags != 0x0100 {
		t.Errorf("flags = %x", flags)
	}
	if qd := binary.BigEndian.Uint16(msg[4:6]); qd != 1 {
		t.Errorf("qdcount = %d", qd)
	}
	if qt := binary.BigEndian.Uint16(msg[25:27]); qt != TypeA {
		t.Errorf("qtype = %d", qt)
	}
	if qc := binary.BigEndian.Uint16(msg[27:29]); qc != ClassIN {
		t.Errorf("qclass = %d", qc)
	}
}

func TestBuildQueryRoot(t *testing.T) {
	msg, err := BuildQuery(1, ".", TypeNS)
	if err != nil {
		t.Fatal(err)
	}
	// header 12 + root 1 + qtr 4
	if len(msg) != 17 {
		t.Fatalf("len = %d, want 17", len(msg))
	}
}

// buildResponse constructs a minimal response with one question and the
// given answer records (pre-encoded rdata) for parser tests.
func buildResponse(t *testing.T, answers []struct {
	name  string
	typ   uint16
	ttl   uint32
	rdata []byte
}) []byte {
	t.Helper()
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:2], 0x4242)
	binary.BigEndian.PutUint16(msg[2:4], 0x8180) // response, RD, NOERROR
	binary.BigEndian.PutUint16(msg[4:6], 1)
	binary.BigEndian.PutUint16(msg[6:8], uint16(len(answers)))
	q, err := EncodeName("example.com")
	if err != nil {
		t.Fatal(err)
	}
	msg = append(msg, q...)
	msg = append(msg, 0, TypeA, 0, ClassIN)
	for _, a := range answers {
		n, err := EncodeName(a.name)
		if err != nil {
			t.Fatal(err)
		}
		msg = append(msg, n...)
		var hdr [10]byte
		binary.BigEndian.PutUint16(hdr[0:2], a.typ)
		binary.BigEndian.PutUint16(hdr[2:4], ClassIN)
		binary.BigEndian.PutUint32(hdr[4:8], a.ttl)
		binary.BigEndian.PutUint16(hdr[8:10], uint16(len(a.rdata)))
		msg = append(msg, hdr[:]...)
		msg = append(msg, a.rdata...)
	}
	return msg
}

func TestParseTypes(t *testing.T) {
	soa := mustConcat(t,
		nameBytes(t, "ns1.example.com"),
		nameBytes(t, "admin.example.com"),
		[]byte{0, 0, 0, 1, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0})
	mx := mustConcat(t, []byte{0, 10}, nameBytes(t, "mail.example.com"))
	msg := buildResponse(t, []struct {
		name  string
		typ   uint16
		ttl   uint32
		rdata []byte
	}{
		{"example.com", TypeA, 300, []byte{93, 184, 216, 34}},
		{"example.com", TypeAAAA, 300, []byte{0x26, 0x06, 0x28, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}},
		{"example.com", TypeTXT, 300, []byte{5, 'h', 'e', 'l', 'l', 'o', 3, 'a', 'b', 'c'}},
		{"example.com", TypeMX, 300, mx},
		{"example.com", TypeSOA, 60, soa},
		{"example.com", 99, 300, []byte{0xde, 0xad}},
	})
	m, err := Parse(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Response || m.Rcode != 0 || m.ID != 0x4242 {
		t.Fatalf("header wrong: %+v", m)
	}
	if len(m.Questions) != 1 || m.Questions[0].Name != "example.com" {
		t.Fatalf("questions: %+v", m.Questions)
	}
	wantData := []string{
		"93.184.216.34",
		"2606:2800::1",
		`"hello" "abc"`,
		"10 mail.example.com",
		"ns1.example.com admin.example.com 1 512 768 1024 1280",
		`\# 2 dead`,
	}
	for i, wd := range wantData {
		if m.Answers[i].Data != wd {
			t.Errorf("answer %d data = %q, want %q", i, m.Answers[i].Data, wd)
		}
	}
	if m.Answers[5].Type != 99 || TypeName(99) != "TYPE99" {
		t.Errorf("unknown type rendering: %+v", m.Answers[5])
	}
}

func nameBytes(t *testing.T, s string) []byte {
	t.Helper()
	b, err := EncodeName(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustConcat(t *testing.T, parts ...[]byte) []byte {
	t.Helper()
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func TestParseCompressionPointer(t *testing.T) {
	// response with an answer name compressed as pointer to the
	// question name at offset 12, plus a rdata name ending in pointer
	// to a suffix. Hand-built to exercise read() jumps.
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:2], 1)
	binary.BigEndian.PutUint16(msg[2:4], 0x8180)
	binary.BigEndian.PutUint16(msg[4:6], 1) // 1 question
	binary.BigEndian.PutUint16(msg[6:8], 1) // 1 answer
	msg = append(msg, nameBytes(t, "example.com")...)
	msg = append(msg, 0, TypeA, 0, ClassIN)
	// answer name: pointer to offset 12
	ptr := []byte{0xC0, 12}
	var hdr [10]byte
	binary.BigEndian.PutUint16(hdr[0:2], TypeCNAMEish)
	binary.BigEndian.PutUint16(hdr[2:4], ClassIN)
	binary.BigEndian.PutUint32(hdr[4:8], 60)
	rd := []byte{3, 'w', 'w', 'w', 0xC0, 12} // "www" + pointer to "example.com" (no null terminator)
	binary.BigEndian.PutUint16(hdr[8:10], uint16(len(rd)))
	msg = append(msg, ptr...)
	msg = append(msg, hdr[:]...)
	msg = append(msg, rd...)

	m, err := Parse(msg)
	if err != nil {
		t.Fatal(err)
	}
	if m.Answers[0].Name != "example.com" {
		t.Errorf("answer name = %q, want example.com", m.Answers[0].Name)
	}
	if m.Answers[0].Data != "www.example.com" {
		t.Errorf("cname data = %q, want www.example.com", m.Answers[0].Data)
	}
}

const TypeCNAMEish = 5

func TestParsePointerLoopGuard(t *testing.T) {
	// answer name is a pointer to itself -> must error, not hang
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:2], 1)
	binary.BigEndian.PutUint16(msg[2:4], 0x8180)
	binary.BigEndian.PutUint16(msg[4:6], 0) // no questions
	binary.BigEndian.PutUint16(msg[6:8], 1)
	// name at offset 12: pointer to 12 (self)
	msg = append(msg, 0xC0, 12)
	var hdr [10]byte
	binary.BigEndian.PutUint16(hdr[0:2], TypeA)
	binary.BigEndian.PutUint16(hdr[8:10], 4)
	msg = append(msg, hdr[:]...)
	msg = append(msg, 1, 2, 3, 4)
	if _, err := Parse(msg); err == nil {
		t.Fatal("self-pointer accepted")
	}
}

func TestParseMalformed(t *testing.T) {
	if _, err := Parse([]byte{1, 2, 3}); err == nil {
		t.Error("short header accepted")
	}
	// header says 1 answer but message ends at the header
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[6:8], 1)
	if _, err := Parse(msg); err == nil {
		t.Error("truncated answer accepted")
	}
	// A record with wrong rdlength
	msg = buildResponse(t, []struct {
		name  string
		typ   uint16
		ttl   uint32
		rdata []byte
	}{{"example.com", TypeA, 60, []byte{1, 2}}})
	if _, err := Parse(msg); err == nil {
		t.Error("bad A length accepted")
	}
	// rdata length runs off the message
	msg = make([]byte, 12)
	binary.BigEndian.PutUint16(msg[4:6], 0)
	binary.BigEndian.PutUint16(msg[6:8], 1)
	n := nameBytes(t, "x.com")
	msg = append(msg, n...)
	var hdr [10]byte
	binary.BigEndian.PutUint16(hdr[0:2], TypeA)
	binary.BigEndian.PutUint16(hdr[8:10], 999) // claim more rdata than exists
	msg = append(msg, hdr[:]...)
	msg = append(msg, 1, 2)
	if _, err := Parse(msg); err == nil {
		t.Error("rdata overflow accepted")
	}
	// TXT string length runs off rdata
	msg = buildResponse(t, []struct {
		name  string
		typ   uint16
		ttl   uint32
		rdata []byte
	}{{"example.com", TypeTXT, 60, []byte{10, 'a', 'b'}}})
	if _, err := Parse(msg); err == nil {
		t.Error("TXT overflow accepted")
	}
}

func TestRcodeAndTypeNames(t *testing.T) {
	if RcodeName(0) != "NOERROR" || RcodeName(2) != "SERVFAIL" || RcodeName(3) != "NXDOMAIN" {
		t.Error("rcode names wrong")
	}
	if RcodeName(42) != "RCODE42" {
		t.Errorf("unknown rcode = %q", RcodeName(42))
	}
	for _, tc := range []struct {
		t16  uint16
		want string
	}{
		{TypeA, "A"}, {TypeAAAA, "AAAA"}, {5, "CNAME"}, {TypeNS, "NS"},
		{TypePTR, "PTR"}, {TypeMX, "MX"}, {TypeTXT, "TXT"}, {TypeSOA, "SOA"},
	} {
		if got := TypeName(tc.t16); got != tc.want {
			t.Errorf("TypeName(%d) = %q, want %q", tc.t16, got, tc.want)
		}
	}
	for _, s := range []string{"A", "AAAA", "CNAME", "NS", "PTR", "MX", "TXT", "SOA"} {
		if _, ok := TypeByName[s]; !ok {
			t.Errorf("TypeByName missing %q", s)
		}
	}
}

func TestReadNameReservedLabel(t *testing.T) {
	// label with type bits 0x40 (EDNS-style reserved) must be rejected
	msg := []byte{0xC0 & ^0xC0, 0} // silence vet; build below explicitly
	msg = []byte{0x40, 3, 'a', 'b', 'c'}
	if _, _, err := ReadName(msg, 0); err == nil {
		t.Error("reserved label accepted")
	}
	// pointer truncated at end
	msg = []byte{0xC0}
	if _, _, err := ReadName(msg, 0); err == nil {
		t.Error("truncated pointer accepted")
	}
	// pointer out of range
	msg = []byte{0xC0, 50}
	if _, _, err := ReadName(msg, 0); err == nil {
		t.Error("out-of-range pointer accepted")
	}
	// label length runs off end
	msg = []byte{10, 'a', 'b'}
	if _, _, err := ReadName(msg, 0); err == nil {
		t.Error("truncated label accepted")
	}
	// name offset past the end of the message
	msg = []byte{0, 0}
	if _, _, err := ReadName(msg, 5); err == nil {
		t.Error("out-of-bounds start accepted")
	}
}

func TestReadNameJumpBudget(t *testing.T) {
	// Deep backward pointer chain: each pointer references the slot
	// immediately before it, so decoding from the tail walks back
	// through more hops than the per-name budget (128, RFC 5343 3.3.3).
	// Every individual pointer is legal; only the chain length is not.
	n := 140
	msg := make([]byte, 2+2*n)
	msg[0] = 0 // chain root: the empty name
	for i := 1; i <= n; i++ {
		binary.BigEndian.PutUint16(msg[2*i:], uint16(0xC000|(2*i-2)))
	}
	if _, _, err := ReadName(msg, 2*n); err == nil {
		t.Fatal("deep pointer chain exceeded jump budget undetected")
	}
	// a chain of 60 hops must still decode fine
	msg2 := make([]byte, 2+2*60)
	msg2[0] = 0
	for i := 1; i <= 60; i++ {
		binary.BigEndian.PutUint16(msg2[2*i:], uint16(0xC000|(2*i-2)))
	}
	name, _, err := ReadName(msg2, 120)
	if err != nil {
		t.Fatalf("shallow chain rejected: %v", err)
	}
	if name != "" {
		t.Errorf("name = %q, want empty (root)", name)
	}
}

func TestReadNamePointerToBrokenName(t *testing.T) {
	// recursion inside a pointer target must propagate the inner error
	// (target at 0: label claims 10 bytes, only 1 exists)
	msg := []byte{10, 'a', 0xC0, 0}
	if _, _, err := ReadName(msg, 2); err == nil {
		t.Error("pointer to malformed name accepted")
	}
}

func TestParseQuestionSectionErrors(t *testing.T) {
	// QDCOUNT=1, name runs off the message end
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[4:6], 1)
	msg = append(msg, 10, 'a', 'b')
	if _, err := Parse(msg); err == nil {
		t.Error("question name overflow accepted")
	}
	// valid question name (root) but qtype/qclass truncated
	msg = make([]byte, 12)
	binary.BigEndian.PutUint16(msg[4:6], 1)
	msg = append(msg, 0, 0xFF, 0xFF)
	if _, err := Parse(msg); err == nil {
		t.Error("truncated question trailer accepted")
	}
	// valid question, but ANCOUNT points past the end
	msg = make([]byte, 12)
	binary.BigEndian.PutUint16(msg[4:6], 1)
	binary.BigEndian.PutUint16(msg[6:8], 1)
	msg = append(msg, 0, 0, TypeA, 0, ClassIN)
	if _, err := Parse(msg); err == nil {
		t.Error("missing answer section accepted")
	}
	// no question, ANCOUNT=1: answer NAME decodes fine (root) but the
	// 10-byte record header is cut off
	msg = make([]byte, 12)
	binary.BigEndian.PutUint16(msg[6:8], 1)
	msg = append(msg, 0, 1, 2, 3, 4, 5)
	if _, err := Parse(msg); err == nil {
		t.Error("truncated record header accepted")
	}
	// ANCOUNT=1, answer NAME itself is a broken label
	msg = make([]byte, 12)
	binary.BigEndian.PutUint16(msg[6:8], 1)
	msg = append(msg, 10, 'a')
	if _, err := Parse(msg); err == nil {
		t.Error("broken answer name accepted")
	}
}

func TestParseRDataErrorBranches(t *testing.T) {
	cases := []struct {
		desc string
		typ  uint16
		rd   []byte
	}{
		{"AAAA wrong length", TypeAAAA, []byte{1, 2, 3, 4}},
		{"CNAME broken name", TypeCNAMEish, []byte{10, 'a', 'b'}},
		{"MX too short", TypeMX, []byte{0, 1}},
		{"MX broken name", TypeMX, []byte{0, 10, 10, 'a', 'b'}},
		{"SOA broken mname", TypeSOA, []byte{10, 'a', 'b'}},
		// mname ok, rname length byte says 9 but only 4 bytes left
		{"SOA broken rname", TypeSOA, []byte{3, 'a', 'b', 'c', 0, 9, 'x', 'y', 'z', 0}},
		// both names ok but only 10 timer bytes instead of 20
		{"SOA timers truncated", TypeSOA, []byte{3, 'a', 'b', 'c', 0, 3, 'd', 'e', 'f', 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}},
	}
	for _, c := range cases {
		msg := buildResponse(t, []struct {
			name  string
			typ   uint16
			ttl   uint32
			rdata []byte
		}{{"example.com", c.typ, 60, c.rd}})
		if _, err := Parse(msg); err == nil {
			t.Errorf("%s accepted", c.desc)
		}
	}
}
