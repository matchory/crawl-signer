package directory

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/matchory/crawl-signer/internal/sign"
)

type backend struct {
	mu    sync.Mutex
	key   ed25519.PrivateKey
	err   error
	calls int
}

func (b *backend) Sign(_ context.Context, msg []byte) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls++
	if b.err != nil {
		return nil, b.err
	}
	return ed25519.Sign(b.key, msg), nil
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newDirectory(t *testing.T) (*Directory, *backend, *clock, ed25519.PublicKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	b := &backend{key: priv}
	c := &clock{t: time.Unix(1795425007, 0)}
	d, err := New(b, pub, "https://Bot.Example.com:443/", c.now)
	if err != nil {
		t.Fatal(err)
	}
	return d, b, c, pub
}

// fetch is a verifier's GET of the directory.
func fetch(d http.Handler) *httptest.ResponseRecorder {
	return get(d, http.MethodGet, "bot.example.com", Path)
}

func get(d http.Handler, method, host, path string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://"+host+path, nil)
	w := httptest.NewRecorder()
	d.ServeHTTP(w, r)
	return w
}

// Guards: G9
func TestServesSignedDirectory(t *testing.T) {
	d, _, _, pub := newDirectory(t)
	// The Host the reverse proxy forwards doesn't change what is signed.
	w := get(d, http.MethodGet, "mirror.example", Path)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	body := w.Body.String()
	x := base64.RawURLEncoding.EncodeToString(pub)
	if body != `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"`+x+`"}]}` {
		t.Errorf("body %s", body)
	}
	h := w.Result().Header
	if ct := h.Get("Content-Type"); ct != "application/http-message-signatures-directory+json" {
		t.Errorf("Content-Type %q", ct)
	}
	sum := sha256.Sum256([]byte(body))
	digest := "sha-256=:" + base64.StdEncoding.EncodeToString(sum[:]) + ":"
	if h.Get("Content-Digest") != digest {
		t.Errorf("Content-Digest %q, want %q", h.Get("Content-Digest"), digest)
	}
	if h.Get("Cache-Control") != "max-age=300" {
		t.Errorf("Cache-Control %q", h.Get("Cache-Control"))
	}

	keyid := sign.Thumbprint(pub)
	params := `("@authority";req "content-digest");created=1795425007;expires=1795428607;keyid="` +
		keyid + `";alg="ed25519";tag="http-message-signatures-directory"`
	if got := h.Get("Signature-Input"); got != "sig1="+params {
		t.Errorf("Signature-Input %q", got)
	}
	base := "\"@authority\";req: bot.example.com\n\"content-digest\": " + digest +
		"\n\"@signature-params\": " + params
	sig := h.Get("Signature")
	raw, err := base64.StdEncoding.DecodeString(
		strings.TrimSuffix(strings.TrimPrefix(sig, "sig1=:"), ":"),
	)
	if err != nil || !ed25519.Verify(pub, []byte(base), raw) {
		t.Errorf("Signature %q doesn't verify over\n%s", sig, base)
	}
}

func TestHead(t *testing.T) {
	d, _, _, _ := newDirectory(t)
	w := get(d, http.MethodHead, "bot.example.com", Path)
	if w.Code != http.StatusOK || w.Body.Len() != 0 || w.Result().Header.Get("Signature") == "" {
		t.Errorf("HEAD: status %d, body %q, headers %v", w.Code, w.Body, w.Result().Header)
	}
}

func TestOtherRequests(t *testing.T) {
	d, b, _, _ := newDirectory(t)
	if w := get(d, http.MethodGet, "bot.example.com", "/"); w.Code != http.StatusNotFound {
		t.Errorf("other path: %d", w.Code)
	}
	w := get(d, http.MethodPost, "bot.example.com", Path)
	if w.Code != http.StatusMethodNotAllowed || w.Result().Header.Get("Allow") != "GET, HEAD" {
		t.Errorf("POST: %d, Allow %q", w.Code, w.Result().Header.Get("Allow"))
	}
	if b.calls != 0 {
		t.Errorf("signed %d times for requests it refused", b.calls)
	}
}

// Guards: G9
func TestResigning(t *testing.T) {
	d, b, c, _ := newDirectory(t)
	first := fetch(d).Result().Header.Get("Signature")

	c.t = c.t.Add(49 * time.Minute)
	got := fetch(d).Result().Header.Get("Signature")
	if got != first || b.calls != 1 {
		t.Errorf("re-signed %d times before the refresh window", b.calls)
	}

	c.t = c.t.Add(2 * time.Minute)
	got = fetch(d).Result().Header.Get("Signature")
	if got == first || b.calls != 2 {
		t.Errorf("not re-signed within 10 minutes of expiry (%d calls)", b.calls)
	}
}

// Guards: G9
func TestBackendDown(t *testing.T) {
	d, b, c, _ := newDirectory(t)
	b.err = errors.New("down")
	if w := fetch(d); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("no signature: status %d, want 503", w.Code)
	}

	b.err = nil
	fetch(d)
	b.err = errors.New("down")
	c.t = c.t.Add(55 * time.Minute)
	if w := fetch(d); w.Code != http.StatusOK {
		t.Errorf("refresh failed with a valid signature cached: status %d", w.Code)
	}

	c.t = c.t.Add(5 * time.Minute)
	if w := fetch(d); w.Code != http.StatusServiceUnavailable {
		t.Errorf("expired signature: status %d, want 503", w.Code)
	}
}

func TestNewRefuses(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	for _, u := range []string{"http://bot.example.com", "https://", "https://a b.example", "::"} {
		if _, err := New(&backend{}, pub, u, time.Now); err == nil {
			t.Errorf("%q: want error", u)
		}
	}
}
