// Package sign produces Web Bot Auth (RFC 9421) signature headers with an
// Ed25519 key, held in memory or in OpenBao or Vault Transit.
package sign

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

// CanonicalAuthority lowercases the authority, converts the host to its
// A-label form (a bracketed IPv6 literal to its RFC 5952 form), drops trailing dots and the scheme's default port, so one site
// maps to one signature regardless of spelling. It returns "" if there is no
// host or it is not valid IDNA; callers must refuse the request.
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
	if host == "" {
		return ""
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
// for an authority Headers would refuse, or one with a byte outside visible
// ASCII.
func SignatureAuthority(scheme, authority string) string {
	// The signature base is text: a byte outside visible ASCII would end a
	// line or fail to match what Envoy sends.
	for i := range len(authority) {
		if authority[i] <= ' ' || authority[i] >= 0x7f {
			return ""
		}
	}

	a := strings.ToLower(authority)
	if i := strings.LastIndex(a, ":"); i >= 0 && !strings.HasSuffix(a, "]") {
		if port := a[i+1:]; (scheme == "https" && port == "443") ||
			(scheme == "http" && port == "80") {
			a = a[:i]
		}
	}
	if CanonicalAuthority("", a) == "" {
		return ""
	}
	return a
}

// Agent is the Signature-Agent: the URL of the key directory, and the form
// the header takes.
type Agent struct {
	URL string
	// Dictionary sends the dictionary form of later Web Bot Auth drafts,
	// sig1="<URL>", covered as "signature-agent";key="sig1". Without it,
	// the header is the structured string "<URL>" of
	// draft-meunier-http-message-signatures-directory-03, which is what
	// Cloudflare verifies.
	Dictionary bool
}

// Header returns the Signature-Agent header value.
func (a Agent) Header() string {
	if a.Dictionary {
		return `sig1="` + a.URL + `"`
	}

	return `"` + a.URL + `"`
}

func (a Agent) component() string {
	if a.Dictionary {
		return `"signature-agent";key="sig1"`
	}

	return `"signature-agent"`
}

// Base returns the RFC 9421 signature base of a Web Bot Auth request
// signature and the Signature-Input value.
func Base(authority string, agent Agent, keyid string, created, expires int64) (string, string) {
	base, params := Params{
		Components: []Component{
			{ID: `"@authority"`, Value: authority},
			{ID: agent.component(), Value: strconv.Quote(agent.URL)},
		},
		Created: created,
		Expires: expires,
		KeyID:   keyid,
		Tag:     "web-bot-auth",
	}.Base()

	return base, "sig1=" + params
}

// Component is a component a signature covers: its identifier as the
// signature base writes it, such as "@authority";req, and its value.
type Component struct {
	ID, Value string
}

// Params are an Ed25519 signature's covered components, in order, and its
// parameters.
type Params struct {
	Components       []Component
	Created, Expires int64
	KeyID, Tag       string
}

// Base returns the RFC 9421 signature base, and the signature parameters
// that follow the label in Signature-Input.
func (p Params) Base() (string, string) {
	ids := make([]string, len(p.Components))

	var b strings.Builder
	for i, c := range p.Components {
		ids[i] = c.ID
		b.WriteString(c.ID + ": " + c.Value + "\n")
	}

	params := fmt.Sprintf(
		`(%s);created=%d;expires=%d;keyid=%q;alg="ed25519";tag=%q`,
		strings.Join(ids, " "),
		p.Created,
		p.Expires,
		p.KeyID,
		p.Tag,
	)
	b.WriteString(`"@signature-params": ` + params)

	return b.String(), params
}
