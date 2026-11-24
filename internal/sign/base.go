// Package sign produces Web Bot Auth signature headers using an OpenBao Transit key.
package sign

import (
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/net/idna"
)

// CanonicalAuthority lowercases the authority, converts the host to its
// A-label form (a bracketed IPv6 literal to its RFC 5952 form), drops trailing dots and the scheme's default port, so one site
// maps to one signature regardless of spelling. It returns "" if the host is
// not valid IDNA; callers must refuse the request.
func CanonicalAuthority(scheme, authority string) string {
	host, port := authority, ""
	if i := strings.LastIndex(authority, ":"); i >= 0 && !strings.HasSuffix(authority, "]") {
		host, port = authority[:i], authority[i+1:]
	}
	if strings.HasPrefix(host, "[") {
		addr, err := netip.ParseAddr(strings.TrimSuffix(host[1:], "]"))
		if !strings.HasSuffix(host, "]") || err != nil || !addr.Is6() || addr.Zone() != "" {
			return ""
		}
		host = "[" + addr.String() + "]"
	} else {
		host = strings.TrimRight(strings.ToLower(host), ".")
		a, err := idna.Lookup.ToASCII(host)
		if err != nil {
			return ""
		}
		host = a
	}
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		return host + ":" + port
	}
	return host
}

// SignatureAuthority is the RFC 9421 @authority for the :authority Envoy
// forwards upstream: lowercased and without the scheme's default port, but
// with a trailing dot kept, since Envoy sends it as received. It returns ""
// for an authority Headers would refuse.
func SignatureAuthority(scheme, authority string) string {
	a := strings.ToLower(authority)
	if i := strings.LastIndex(a, ":"); i >= 0 && !strings.HasSuffix(a, "]") {
		if port := a[i+1:]; (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
			a = a[:i]
		}
	}
	if c := CanonicalAuthority("", a); c == "" || c[0] == ':' {
		return ""
	}
	return a
}

// Base returns the RFC 9421 signature base and the Signature-Input value.
func Base(authority, agent, keyid string, created, expires int64) (base, input string) {
	params := fmt.Sprintf(`("@authority" "signature-agent";key="sig1");created=%d;expires=%d;keyid=%q;alg="ed25519";tag="web-bot-auth"`,
		created, expires, keyid)
	base = fmt.Sprintf("\"@authority\": %s\n\"signature-agent\";key=\"sig1\": %q\n\"@signature-params\": %s",
		authority, agent, params)
	return base, "sig1=" + params
}
