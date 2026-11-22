// Package dns implements the subset of the DNS wire protocol (RFC 1035,
// A/AAAA/CNAME/NS/PTR/MX/TXT/SOA) needed to build queries and parse
// responses with no third-party dependency. Pure Go stdlib.
package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

// Record type numbers we recognize.
const (
	TypeA    = 1
	TypeNS   = 2
	TypeSOA  = 6
	TypePTR  = 12
	TypeMX   = 15
	TypeTXT  = 16
	TypeAAAA = 28
	ClassIN  = 1
)

// TypeByName maps a -type flag value to its wire number.
var TypeByName = map[string]uint16{
	"A": TypeA, "AAAA": TypeAAAA, "CNAME": 5, "NS": TypeNS,
	"PTR": TypePTR, "MX": TypeMX, "TXT": TypeTXT, "SOA": TypeSOA,
}

// TypeName returns the display name for a record type number.
func TypeName(t uint16) string {
	switch t {
	case TypeA:
		return "A"
	case TypeNS:
		return "NS"
	case 5:
		return "CNAME"
	case TypeSOA:
		return "SOA"
	case TypePTR:
		return "PTR"
	case TypeMX:
		return "MX"
	case TypeTXT:
		return "TXT"
	case TypeAAAA:
		return "AAAA"
	default:
		return fmt.Sprintf("TYPE%d", t)
	}
}

var rcodeNames = map[uint16]string{
	0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
	4: "NOTIMP", 5: "REFUSED",
	6: "BADVERS", 7: "BADSIG", 8: "BADKEY", 9: "BADTIME", 10: "BADTRUNC",
}

// RcodeName returns the display name for a response code number.
func RcodeName(rc uint16) string {
	if n, ok := rcodeNames[rc]; ok {
		return n
	}
	return fmt.Sprintf("RCODE%d", rc)
}

// ErrMalformed marks any parse failure of a DNS message.
var ErrMalformed = errors.New("malformed dns message")

// Record is one resource record from the answer section.
type Record struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	// Data holds the decoded rdata: an IP, a domain name, quoted TXT
	// strings joined by spaces, "pref exchange" for MX, or SOA fields.
	Data string
}

// Message is a decoded DNS response.
type Message struct {
	ID        uint16
	Response  bool
	Opcode    uint16
	Rcode     uint16
	TC        bool // answer truncated: retry over TCP
	Questions []Question
	Answers   []Record
}

// Question is one question-section entry.
type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

// EncodeName writes a domain name into wire label format
// (len-prefixed labels, zero-terminated). No compression on output.
func EncodeName(name string) ([]byte, error) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if name == "" {
		return []byte{0}, nil // root
	}
	var buf []byte
	for _, label := range strings.Split(name, ".") {
		if label == "" {
			return nil, fmt.Errorf("%w: empty label in %q", ErrMalformed, name)
		}
		if len(label) > 63 {
			return nil, fmt.Errorf("%w: label too long in %q", ErrMalformed, name)
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	buf = append(buf, 0)
	if len(buf) > 255 {
		return nil, fmt.Errorf("%w: name too long (%d bytes)", ErrMalformed, len(buf))
	}
	return buf, nil
}

// BuildQuery assembles a standard recursive query message.
func BuildQuery(id uint16, name string, qtype uint16) ([]byte, error) {
	qname, err := EncodeName(name)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 12, 12+len(qname)+4)
	binary.BigEndian.PutUint16(buf[0:2], id)
	binary.BigEndian.PutUint16(buf[2:4], 0x0100) // RD desired
	binary.BigEndian.PutUint16(buf[4:6], 1)      // QDCOUNT
	buf = append(buf, qname...)
	var e [4]byte
	binary.BigEndian.PutUint16(e[0:2], qtype)
	binary.BigEndian.PutUint16(e[2:4], ClassIN)
	buf = append(buf, e[:]...)
	return buf, nil
}

// nameReader decodes names with compression-pointer support. The jumps
// argument is a per-name recursion budget (RFC 5343 section 3.3.3:
// pointer chains must terminate; we cap them to survive hostile data).
type nameReader struct {
	msg []byte
}

// read decodes a name starting at sequential offset pos. It returns the
// name and the offset to continue sequential parsing after the name's
// encoding (which for a pointer is pos+2 plus any further labels).
func (nr *nameReader) read(pos int, jumps int) (string, int, error) {
	var labels []string
	scur := pos
	for {
		if scur >= len(nr.msg) {
			return "", 0, fmt.Errorf("%w: name runs off end of message", ErrMalformed)
		}
		l := int(nr.msg[scur])
		if l == 0 {
			return strings.Join(labels, "."), scur + 1, nil
		}
		if l&0xC0 == 0xC0 { // compression pointer
			if scur+2 > len(nr.msg) {
				return "", 0, fmt.Errorf("%w: truncated pointer", ErrMalformed)
			}
			ptr := int(binary.BigEndian.Uint16(nr.msg[scur:]) & 0x3FFF)
			next := scur + 2
			if jumps <= 0 {
				return "", 0, fmt.Errorf("%w: compression pointer loop", ErrMalformed)
			}
			if ptr >= scur || ptr >= len(nr.msg) {
				// pointers must reference an earlier position
				// (loop guard per RFC 5343 section 3.3.3)
				return "", 0, fmt.Errorf("%w: pointer %d out of range", ErrMalformed, ptr)
			}
			rest, _, err := nr.read(ptr, jumps-1)
			if err != nil {
				return "", 0, err
			}
			if rest != "" {
				labels = append(labels, rest)
			}
			// a pointer terminates the name; sequential
			// parsing resumes right after the pointer (RFC 1035 4.1.4)
			return strings.Join(labels, "."), next, nil
		}
		if l&0xC0 != 0 {
			return "", 0, fmt.Errorf("%w: reserved label type 0x%X", ErrMalformed, l&0xC0)
		}
		if scur+1+l > len(nr.msg) {
			return "", 0, fmt.Errorf("%w: label runs off end", ErrMalformed)
		}
		labels = append(labels, strings.ToLower(string(nr.msg[scur+1:scur+1+l])))
		scur += 1 + l
	}
}

// ReadName decodes a name starting at pos in msg.
func ReadName(msg []byte, pos int) (string, int, error) {
	nr := &nameReader{msg: msg}
	return nr.read(pos, 128)
}

// Parse decodes a full DNS message (a query or a response).
func Parse(msg []byte) (*Message, error) {
	if len(msg) < 12 {
		return nil, fmt.Errorf("%w: short header (%d bytes)", ErrMalformed, len(msg))
	}
	m := &Message{}
	m.ID = binary.BigEndian.Uint16(msg[0:2])
	flags := binary.BigEndian.Uint16(msg[2:4])
	m.Response = flags&0x8000 != 0
	m.Opcode = (flags >> 11) & 0xF
	m.Rcode = flags & 0xF
	m.TC = flags&0x0200 != 0
	qd := int(binary.BigEndian.Uint16(msg[4:6]))
	an := int(binary.BigEndian.Uint16(msg[6:8]))
	pos := 12
	nr := &nameReader{msg: msg}
	for i := 0; i < qd; i++ {
		name, next, err := nr.read(pos, 128)
		if err != nil {
			return nil, err
		}
		if next+4 > len(msg) {
			return nil, fmt.Errorf("%w: question qtype/qclass cut off", ErrMalformed)
		}
		m.Questions = append(m.Questions, Question{
			Name:  name,
			Type:  binary.BigEndian.Uint16(msg[next : next+2]),
			Class: binary.BigEndian.Uint16(msg[next+2 : next+4]),
		})
		pos = next + 4
	}
	for i := 0; i < an; i++ {
		name, next, err := nr.read(pos, 128)
		if err != nil {
			return nil, err
		}
		if next+10 > len(msg) {
			return nil, fmt.Errorf("%w: record header cut off", ErrMalformed)
		}
		typ := binary.BigEndian.Uint16(msg[next : next+2])
		cls := binary.BigEndian.Uint16(msg[next+2 : next+4])
		ttl := binary.BigEndian.Uint32(msg[next+4 : next+8])
		rdlen := int(binary.BigEndian.Uint16(msg[next+8 : next+10]))
		rdpos := next + 10
		if rdpos+rdlen > len(msg) {
			return nil, fmt.Errorf("%w: rdata runs off end", ErrMalformed)
		}
		data, err := decodeRData(nr, rdpos, rdlen, typ)
		if err != nil {
			return nil, err
		}
		m.Answers = append(m.Answers, Record{Name: name, Type: typ, Class: cls, TTL: ttl, Data: data})
		pos = rdpos + rdlen
	}
	return m, nil
}

// decodeRData renders one record's rdata as display text. rdpos is the
// absolute offset of the rdata inside nr.msg so name decompression works.
func decodeRData(nr *nameReader, rdpos, rdlen int, typ uint16) (string, error) {
	end := rdpos + rdlen
	switch typ {
	case TypeA:
		if rdlen != 4 {
			return "", fmt.Errorf("%w: A rdata length %d", ErrMalformed, rdlen)
		}
		return net.IP(nr.msg[rdpos:end]).String(), nil
	case TypeAAAA:
		if rdlen != 16 {
			return "", fmt.Errorf("%w: AAAA rdata length %d", ErrMalformed, rdlen)
		}
		return net.IP(nr.msg[rdpos:end]).String(), nil
	case 5, TypeNS, TypePTR: // CNAME, NS, PTR
		name, _, err := nr.read(rdpos, 128)
		if err != nil {
			return "", err
		}
		return name, nil
	case TypeMX:
		if rdlen < 3 {
			return "", fmt.Errorf("%w: MX rdata too short", ErrMalformed)
		}
		pref := binary.BigEndian.Uint16(nr.msg[rdpos : rdpos+2])
		name, _, err := nr.read(rdpos+2, 128)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%d %s", pref, name), nil
	case TypeTXT:
		var parts []string
		for i := rdpos; i < end; {
			l := int(nr.msg[i])
			if i+1+l > end {
				return "", fmt.Errorf("%w: TXT string runs off rdata", ErrMalformed)
			}
			parts = append(parts, fmt.Sprintf("%q", string(nr.msg[i+1:i+1+l])))
			i += 1 + l
		}
		return strings.Join(parts, " "), nil
	case TypeSOA:
		mname, off, err := nr.read(rdpos, 128)
		if err != nil {
			return "", err
		}
		rname, off2, err := nr.read(off, 128)
		if err != nil {
			return "", err
		}
		if off2+20 > end {
			return "", fmt.Errorf("%w: SOA timers cut off", ErrMalformed)
		}
		t := nr.msg[off2 : off2+20]
		return fmt.Sprintf("%s %s %d %d %d %d %d", mname, rname,
			binary.BigEndian.Uint32(t[0:4]), binary.BigEndian.Uint32(t[4:8]),
			binary.BigEndian.Uint32(t[8:12]), binary.BigEndian.Uint32(t[12:16]),
			binary.BigEndian.Uint32(t[16:20])), nil
	default:
		// Unknown type: RFC 3597 generic format so the answer stays visible.
		return fmt.Sprintf("\\# %d %x", rdlen, nr.msg[rdpos:end]), nil
	}
}
