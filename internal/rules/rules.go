// Package rules holds the static request rules the gateway enforces before signing.
package rules

import (
	"net"
	"net/netip"
	"strings"
)

type Header struct{ Name, Value string }

type Request struct {
	Method, Scheme, Authority, Path string
	Headers                         []Header
}

type Verdict struct {
	OK     bool
	Status int
	Reason string
}

// Same ranges as the platform's squid egress proxy.
var internal = mustPrefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4",
	"::1/128", "fc00::/7", "fe80::/10", "ff00::/8",
)

func mustPrefixes(s ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(s))
	for i, p := range s {
		out[i] = netip.MustParsePrefix(p)
	}
	return out
}

func Check(r Request) Verdict {
	if r.Method != "GET" && r.Method != "HEAD" {
		return Verdict{false, 405, "method"}
	}
	for _, h := range r.Headers {
		switch strings.ToLower(h.Name) {
		case "transfer-encoding":
			return Verdict{false, 413, "body"}
		case "content-length":
			if strings.TrimSpace(h.Value) != "0" {
				return Verdict{false, 413, "body"}
			}
		}
	}

	if r.Scheme != "http" && r.Scheme != "https" {
		return Verdict{false, 403, "scheme"}
	}

	// Userinfo would make the authority disagree with what the upstream dials.
	if strings.Contains(r.Authority, "@") {
		return Verdict{false, 403, "target"}
	}
	host, port := r.Authority, ""
	if h, p, err := net.SplitHostPort(r.Authority); err == nil {
		if p == "" {
			return Verdict{false, 403, "target"}
		}
		host, port = h, p
	} else {
		host = strings.TrimSuffix(strings.TrimPrefix(r.Authority, "["), "]")
	}
	want := "80"
	if r.Scheme == "https" {
		want = "443"
	}
	if port == "" {
		port = want
	}
	if port != want {
		return Verdict{false, 403, "port"}
	}

	if isInternal(host) {
		return Verdict{false, 403, "target"}
	}
	return Verdict{OK: true}
}

func isInternal(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	if looksNumeric(host) {
		if a, err := netip.ParseAddr(host); err != nil || !a.Is4() {
			return true
		}
	}
	// Zone IDs and IPv4-mapped forms must not slip past the prefix match.
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.WithZone("").Unmap()
	for _, p := range internal {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// looksNumeric spots forms like 127.1, 0x7f.1 or 2130706433 that resolvers
// read as IPv4 but netip rejects, so they would otherwise pass as hostnames.
func looksNumeric(host string) bool {
	last := host[strings.LastIndexByte(host, '.')+1:]
	if last == "" || last[0] < '0' || last[0] > '9' {
		return false
	}
	return strings.Trim(host, "0123456789abcdefABCDEFxX.") == ""
}

var allowed = map[string]bool{
	"accept": true, "accept-language": true, "accept-encoding": true,
	"if-none-match": true, "if-modified-since": true, "range": true,
}

// Allowlist keeps only headers the gateway lets through and names the rest.
func Allowlist(h []Header) (keep []Header, drop []string) {
	for _, x := range h {
		if allowed[strings.ToLower(x.Name)] {
			keep = append(keep, x)
		} else {
			drop = append(drop, x.Name)
		}
	}
	return keep, drop
}
