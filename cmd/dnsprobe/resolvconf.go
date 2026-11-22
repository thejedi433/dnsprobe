package main

import (
	"bufio"
	"os"
	"strings"
)

// systemResolvers reads nameserver entries from /etc/resolv.conf.
// Windows and macOS have no equivalent file; fall back to a well-known
// public resolver so the tool still works there without -servers.
func systemResolvers() []string {
	return resolversFrom("/etc/resolv.conf")
}

func resolversFrom(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return []string{"8.8.8.8"}
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if i := strings.IndexByte(line, ';'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.EqualFold(fields[0], "nameserver") {
			out = append(out, fields[1])
		}
	}
	if len(out) == 0 {
		return []string{"8.8.8.8"}
	}
	return out
}
