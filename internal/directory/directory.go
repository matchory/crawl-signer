// Package directory serves the Web Bot Auth key directory: the signing key's
// public part as a JSON Web Key Set, signed with the key itself to prove that
// the directory's owner holds it.
package directory

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/matchory/crawl-signer/internal/sign"
)

// Path is where verifiers look for the directory.
const Path = "/.well-known/http-message-signatures-directory"

const (
	mediaType = "application/http-message-signatures-directory+json"
	validity  = time.Hour
	// refresh is when to re-sign before expiry. It is longer than the
	// Cache-Control max-age, so a cached copy still holds a valid signature.
	refresh = 10 * time.Minute
	maxAge  = "max-age=300"
)

type signature struct {
	params, value string
}

// Directory is an http.Handler for the key directory.
type Directory struct {
	b         sign.Backend
	authority string
	keyid     string
	body      []byte
	digest    string
	now       func() time.Time
	w         *sign.Window[signature]
}

// New returns a Directory for the public key pub, signed through b for the
// authority of agentURL, the Signature-Agent: whatever Host a request names,
// the proof only holds for that authority, so a copy elsewhere doesn't verify.
func New(
	b sign.Backend,
	pub ed25519.PublicKey,
	agentURL string,
	now func() time.Time,
) (*Directory, error) {
	u, err := url.Parse(agentURL)
	if err != nil || u.Scheme != "https" {
		return nil, errors.New("directory: signature_agent must be an https:// URL")
	}

	authority := sign.CanonicalAuthority("https", u.Host)
	if authority == "" {
		return nil, fmt.Errorf("directory: invalid authority %q", u.Host)
	}

	body := []byte(`{"keys":[{"kty":"OKP","crv":"Ed25519","x":"` +
		base64.RawURLEncoding.EncodeToString(pub) + `"}]}`)
	sum := sha256.Sum256(body)

	return &Directory{
		b:         b,
		authority: authority,
		keyid:     sign.Thumbprint(pub),
		body:      body,
		digest:    "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":",
		now:       now,
		w:         sign.NewWindow[signature](int64(refresh / time.Second)),
	}, nil
}

// ServeHTTP answers GET and HEAD for Path. Without a valid signature it
// answers 503, since an unsigned directory fails verification anyway.
func (d *Directory) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != Path {
		http.NotFound(w, r)
		return
	}

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)

		return
	}

	sig, err := d.signature(r.Context())
	if err != nil {
		http.Error(w, "directory signature unavailable", http.StatusServiceUnavailable)
		return
	}

	h := w.Header()
	h.Set("Content-Type", mediaType)
	h.Set("Content-Digest", d.digest)
	h.Set("Cache-Control", maxAge)
	h.Set("Signature-Input", "sig1="+sig.params)
	h.Set("Signature", "sig1=:"+sig.value+":")

	if r.Method == http.MethodHead {
		return
	}

	_, _ = w.Write(d.body)
}

// signature returns the cached signature, re-signing within refresh of its
// expiry. If re-signing fails, an unexpired signature is still served.
func (d *Directory) signature(ctx context.Context) (signature, error) {
	created := d.now().Unix()

	return d.w.Get("", created, func() (signature, int64, error) {
		expires := created + int64(validity/time.Second)
		base, params := sign.Params{
			Components: []sign.Component{
				{ID: `"@authority";req`, Value: d.authority},
				{ID: `"content-digest"`, Value: d.digest},
			},
			Created: created,
			Expires: expires,
			KeyID:   d.keyid,
			Tag:     "http-message-signatures-directory",
		}.Base()

		raw, err := d.b.Sign(context.WithoutCancel(ctx), []byte(base))
		if err != nil {
			return signature{}, 0, err
		}

		return signature{
			params: params,
			value:  base64.StdEncoding.EncodeToString(raw),
		}, expires, nil
	})
}
