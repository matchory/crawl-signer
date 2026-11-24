// Package sign produces Web Bot Auth signature headers using an OpenBao Transit key.
package sign

import (
	"fmt"
	"strings"

	"golang.org/x/net/idna"
)

// CanonicalAuthority lowercases the authority, converts the host to its
// A-label form and strips the scheme's default port, so one site maps to one
// signature regardless of spelling.
func CanonicalAuthority(scheme, authority string) string {
	host, port := authority, ""
	if i := strings.LastIndex(authority, ":"); i >= 0 && !strings.HasSuffix(authority, "]") {
		host, port = authority[:i], authority[i+1:]
	}
	host = strings.ToLower(host)
	if a, err := idna.Lookup.ToASCII(host); err == nil {
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

// Base returns the RFC 9421 signature base and the Signature-Input value.
func Base(authority, agent, keyid string, created, expires int64) (base, input string) {
	params := fmt.Sprintf(`("@authority" "signature-agent";key="sig1");created=%d;expires=%d;keyid=%q;alg="ed25519";tag="web-bot-auth"`,
		created, expires, keyid)
	base = fmt.Sprintf("\"@authority\": %s\n\"signature-agent\";key=\"sig1\": %q\n\"@signature-params\": %s",
		authority, agent, params)
	return base, "sig1=" + params
}
