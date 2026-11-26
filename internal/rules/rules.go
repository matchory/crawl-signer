// Package rules holds the static request rules the gateway enforces before signing.
package rules

import (
	"net/netip"
	"strings"
)

// Header is one HTTP header.
type Header struct{ Name, Value string }

// Request is what the rules look at.
type Request struct {
	Method, Scheme, Authority, Path string
	Headers                         []Header
}

// Verdict is the rules' decision: OK, or the status and reason of the
// refusal.
type Verdict struct {
	OK     bool
	Status int
	Reason string
}

// Private, loopback, link-local, shared, benchmarking, multicast and reserved
// ranges, and the IPv6 ranges that embed an IPv4 address.
var internal = mustPrefixes(
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"::/128",
	"::1/128",
	"100::/64",
	"fc00::/7",
	"fe80::/10",
	"fec0::/10",
	"ff00::/8",
	// IPv4-compatible, SIIT, NAT64, Teredo and 6to4 embed an IPv4 address that may be internal.
	"::/96",
	"::ffff:0:0:0/96",
	"64:ff9b::/96",
	"64:ff9b:1::/48",
	"2001::/32",
	"2002::/16",
)

func mustPrefixes(s ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(s))
	for i, p := range s {
		out[i] = netip.MustParsePrefix(p)
	}
	return out
}

// Check applies the static rules: method, body, scheme, port and target.
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

	scheme := strings.ToLower(r.Scheme)
	if scheme != "http" && scheme != "https" {
		return Verdict{false, 403, "scheme"}
	}

	host, port, ok := parseAuthority(r.Authority)
	if !ok {
		return Verdict{false, 403, "target"}
	}
	want := "80"
	if scheme == "https" {
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

// parseAuthority is deliberately strict: anything it cannot classify
// unambiguously is refused rather than guessed at.
func parseAuthority(a string) (string, string, bool) {
	if strings.Contains(a, "@") {
		return "", "", false
	}

	host, port, hasPort, ok := splitHostPort(a)
	if !ok || hasPort && port == "" {
		return "", "", false
	}

	for _, c := range port {
		if c < '0' || c > '9' {
			return "", "", false
		}
	}

	return host, port, true
}

// splitHostPort splits a bracketed IPv6 literal or a hostname from its port.
func splitHostPort(a string) (string, string, bool, bool) {
	if strings.HasPrefix(a, "[") {
		end := strings.IndexByte(a, ']')
		if end < 0 {
			return "", "", false, false
		}

		// A zone names an interface of the sender; it has no meaning in a
		// URL's authority.
		addr, err := netip.ParseAddr(a[1:end])
		if err != nil || !addr.Is6() || addr.Zone() != "" {
			return "", "", false, false
		}

		rest := a[end+1:]
		if rest == "" {
			return addr.String(), "", false, true
		}

		if rest[0] != ':' {
			return "", "", false, false
		}

		return addr.String(), rest[1:], true, true
	}

	if strings.Count(a, ":") > 1 {
		return "", "", false, false
	}

	host, port, hasPort := strings.Cut(a, ":")
	for _, c := range host {
		if !hostChar(c) {
			return "", "", false, false
		}
	}

	host = strings.TrimRight(host, ".")

	return host, port, hasPort, host != ""
}

func hostChar(c rune) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '-' || c == '.' || c == '_'
}

func isInternal(host string) bool {
	host = strings.ToLower(host)
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	if looksNumeric(host) {
		if a, err := netip.ParseAddr(host); err != nil || !a.Is4() {
			return true
		}
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
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
func Allowlist(h []Header) ([]Header, []string) {
	var (
		keep []Header
		drop []string
	)

	for _, x := range h {
		if allowed[strings.ToLower(x.Name)] {
			keep = append(keep, x)
		} else {
			drop = append(drop, x.Name)
		}
	}
	return keep, drop
}
