package sign

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/matchory/crawl-signer/internal/rules"
)

func TestCanonicalAuthority(t *testing.T) {
	for _, c := range []struct{ scheme, in, want string }{
		{"https", "Example.COM:443", "example.com"},
		{"http", "example.com:80", "example.com"},
		{"https", "example.com:8443", "example.com:8443"},
		{"https", "bücher.de", "xn--bcher-kva.de"},
		{"https", "Example.com.", "example.com"},
		{"https", "a b.com", ""},
		{"https", "[2001:DB8::1]:443", "[2001:db8::1]"},
		{"https", "[2001:db8:0::1]:8443", "[2001:db8::1]:8443"},
		{"https", "[fe80::1%eth0]", ""},
		{"https", "[example.com]", ""},
		{"https", "[1.2.3.4]", ""},
		// No host: nothing to sign for or cache under.
		{"https", ":8443", ""},
		{"https", ".:8443", ""},
		{"https", "", ""},
	} {
		if got := CanonicalAuthority(c.scheme, c.in); got != c.want {
			t.Errorf("%s %s: got %q, want %q", c.scheme, c.in, got, c.want)
		}
	}
}

const wantBase = `"@authority": example.com
"signature-agent";key="sig1": "https://bot.example.com"
"@signature-params": ("@authority" "signature-agent";key="sig1");created=1795425000;expires=1795425060;keyid="K";alg="ed25519";tag="web-bot-auth"`

// The base for the structured-string form Cloudflare verifies: no key
// parameter anywhere.
const wantStringBase = `"@authority": example.com
"signature-agent": "https://bot.example.com"
"@signature-params": ("@authority" "signature-agent");created=1795425000;expires=1795425060;keyid="K";alg="ed25519";tag="web-bot-auth"`

func TestBaseString(t *testing.T) {
	base, input := Base(
		"example.com",
		Agent{URL: "https://bot.example.com"},
		"K",
		1795425000,
		1795425060,
	)
	if base != wantStringBase {
		t.Errorf("base:\n%s\nwant:\n%s", base, wantStringBase)
	}
	if strings.Contains(input, "key=") {
		t.Errorf("input has a key parameter: %q", input)
	}
	if h := (Agent{URL: "https://bot.example.com"}).Header(); h != `"https://bot.example.com"` {
		t.Errorf("header %q", h)
	}
	if h := (Agent{URL: "https://bot.example.com", Dictionary: true}).Header(); h != `sig1="https://bot.example.com"` {
		t.Errorf("dictionary header %q", h)
	}
}

func TestBaseDictionary(t *testing.T) {
	base, input := Base(
		"example.com",
		Agent{URL: "https://bot.example.com", Dictionary: true},
		"K",
		1795425000,
		1795425060,
	)
	if base != wantBase {
		t.Errorf("base:\n%s\nwant:\n%s", base, wantBase)
	}
	_, params, _ := strings.Cut(wantBase, `"@signature-params": `)
	if input != "sig1="+params {
		t.Errorf("input: got %q", input)
	}
}

type fakeBackend struct {
	priv    ed25519.PrivateKey
	calls   atomic.Int32
	gate    chan struct{}
	entered chan struct{}
	err     error
}

func (f *fakeBackend) Sign(ctx context.Context, msg []byte) ([]byte, error) {
	f.calls.Add(1)
	if f.gate != nil {
		f.entered <- struct{}{}
		<-f.gate
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	if f.err != nil {
		return nil, f.err
	}
	return ed25519.Sign(f.priv, msg), nil
}

func newFake(t *testing.T) (*fakeBackend, ed25519.PublicKey) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeBackend{priv: priv}, pub
}

var agent = Agent{URL: "https://bot.example.com"}

func hmap(hs []rules.Header) map[string]string {
	m := map[string]string{}
	for _, h := range hs {
		m[h.Name] = h.Value
	}
	return m
}

// Guards: G5
func TestSignatureVerifies(t *testing.T) {
	fb, pub := newFake(t)
	now := time.Unix(1795425007, 0)
	s := NewSigner(fb, agent, "K", func() time.Time { return now })
	hs, err := s.Headers(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	m := hmap(hs)
	if m["Signature-Agent"] != `"https://bot.example.com"` {
		t.Errorf("Signature-Agent: %q", m["Signature-Agent"])
	}
	base, input := Base("example.com", agent, "K", 1795425000, 1795425060)
	if m["Signature-Input"] != input {
		t.Errorf("Signature-Input: %q, want %q", m["Signature-Input"], input)
	}
	v := strings.TrimSuffix(strings.TrimPrefix(m["Signature"], "sig1=:"), ":")
	sig, err := base64.StdEncoding.DecodeString(v)
	if err != nil || !ed25519.Verify(pub, []byte(base), sig) {
		t.Errorf("signature does not verify: %q (%v)", m["Signature"], err)
	}
}

// Guards: G5
func TestWindowCache(t *testing.T) {
	fb, _ := newFake(t)
	now := time.Unix(1795425007, 0)
	s := NewSigner(fb, agent, "K", func() time.Time { return now })
	ctx := context.Background()
	h1, _ := s.Headers(ctx, "example.com")
	h2, _ := s.Headers(ctx, "example.com")
	if fb.calls.Load() != 1 {
		t.Fatalf("calls = %d, want 1", fb.calls.Load())
	}
	if !strings.Contains(hmap(h1)["Signature-Input"], "created=1795425000;") ||
		hmap(h1)["Signature"] != hmap(h2)["Signature"] {
		t.Errorf("unexpected headers %v", h1)
	}
	s.Headers(ctx, "other.example")
	if fb.calls.Load() != 2 {
		t.Errorf("other authority: calls = %d, want 2", fb.calls.Load())
	}
	now = time.Unix(1795425050, 0)
	h3, _ := s.Headers(ctx, "example.com")
	if fb.calls.Load() != 3 {
		t.Errorf("past expires-10: calls = %d, want 3", fb.calls.Load())
	}
	if in := hmap(h3)["Signature-Input"]; !strings.Contains(
		in,
		"created=1795425030;expires=1795425090;",
	) {
		t.Errorf("re-sign window: %q", in)
	}
}

// Guards: G1
func TestTransitDown(t *testing.T) {
	fb, _ := newFake(t)
	now := time.Unix(1795425007, 0)
	s := NewSigner(fb, agent, "K", func() time.Time { return now })
	ctx := context.Background()
	if _, err := s.Headers(ctx, "example.com"); err != nil {
		t.Fatal(err)
	}
	fb.err = errors.New("down")
	if _, err := s.Headers(ctx, "example.com"); err != nil {
		t.Errorf("cached entry should be served: %v", err)
	}
	if _, err := s.Headers(ctx, "fresh.example"); err == nil {
		t.Error("want error with no cache entry")
	}
	// Refresh window failing: the still-valid entry is served.
	now = time.Unix(1795425055, 0)
	if _, err := s.Headers(ctx, "example.com"); err != nil {
		t.Errorf("still-valid entry should be served on refresh failure: %v", err)
	}
	now = time.Unix(1795425061, 0)
	if _, err := s.Headers(ctx, "example.com"); err == nil {
		t.Error("expired entry must not be served")
	}
}

func unixServer(t *testing.T, h http.Handler) string {
	// t.TempDir's path, which holds the test's name, can exceed the 104
	// bytes macOS allows a socket path.
	dir, err := os.MkdirTemp("", "sign") //nolint:usetesting // see above
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "bao.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.Listener = l
	srv.Start()
	t.Cleanup(srv.Close)
	return sock
}

func TestTransitWire(t *testing.T) {
	sock := unixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var body struct {
			Input      string `json:"input"`
			KeyVersion int    `json:"key_version"`
		}
		json.Unmarshal(b, &body)
		if r.Method != "POST" || r.URL.Path != "/v1/transit/sign/web-bot-auth" ||
			body.Input != base64.StdEncoding.EncodeToString([]byte("msg")) || body.KeyVersion != 3 {
			t.Errorf("bad request %s %s %s", r.Method, r.URL.Path, b)
		}
		w.Write(
			[]byte(
				`{"data":{"signature":"vault:v3:` + base64.StdEncoding.EncodeToString(
					[]byte("sigbytes"),
				) + `"}}`,
			),
		)
	}))
	got, err := mustTransit(
		t,
		"unix://"+sock,
		"web-bot-auth",
		3,
	).Sign(context.Background(), []byte("msg"))
	if err != nil || string(got) != "sigbytes" {
		t.Errorf("got %q, %v", got, err)
	}
}

func TestTransitStatusError(t *testing.T) {
	sock := unixServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "secret-detail", http.StatusServiceUnavailable)
	}))
	_, err := mustTransit(t, "unix://"+sock, "k", 1).Sign(context.Background(), []byte("m"))
	if err == nil || !strings.Contains(err.Error(), "503") ||
		strings.Contains(err.Error(), "secret-detail") {
		t.Errorf("err = %v", err)
	}
}

func TestTransitTimeout(t *testing.T) {
	sock := unixServer(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
	}))
	start := time.Now()
	_, err := mustTransit(t, "unix://"+sock, "k", 1).Sign(context.Background(), []byte("m"))
	if err == nil || time.Since(start) > 4*time.Second {
		t.Errorf("err = %v after %v, want timeout near 2s", err, time.Since(start))
	}
}

func TestConcurrentMissesShareOneCall(t *testing.T) {
	fb, _ := newFake(t)
	fb.gate = make(chan struct{})
	fb.entered = make(chan struct{}, 8)
	s := NewSigner(fb, agent, "K", func() time.Time { return time.Unix(1795425007, 0) })
	ctx1, cancel1 := context.WithCancel(context.Background())
	errs := make(chan error, 8)
	call := func(ctx context.Context) {
		_, err := s.Headers(ctx, "example.com")
		errs <- err
	}
	go call(ctx1)
	select {
	case <-fb.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("backend never called")
	}
	for range 7 {
		go call(context.Background())
	}
	cancel1()
	close(fb.gate)
	for i := range 8 {
		select {
		case err := <-errs:
			if err != nil {
				t.Errorf("caller %d: %v", i, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("callers did not return")
		}
	}
	if n := fb.calls.Load(); n != 1 {
		t.Errorf("calls = %d, want 1", n)
	}
}

func TestInvalidAuthorityNotSigned(t *testing.T) {
	fb, _ := newFake(t)
	s := NewSigner(fb, agent, "K", func() time.Time { return time.Unix(1795425007, 0) })
	for _, a := range []string{"", ".", ":443"} {
		if _, err := s.Headers(context.Background(), a); err == nil {
			t.Errorf("%q: want error", a)
		}
	}
	if fb.calls.Load() != 0 {
		t.Errorf("backend called %d times", fb.calls.Load())
	}
}

func TestTransitEscapesKey(t *testing.T) {
	sock := unixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != "/v1/transit/sign/a%2Fb" {
			t.Errorf("path %q", r.URL.EscapedPath())
		}
		w.Write([]byte(`{"data":{"signature":"vault:v1:AA=="}}`))
	}))
	if _, err := mustTransit(
		t,
		"unix://"+sock,
		"a/b",
		1,
	).Sign(context.Background(), []byte("m")); err != nil {
		t.Error(err)
	}
}

func TestTransitBodyCap(t *testing.T) {
	sock := unixServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"data":{"signature":"vault:v1:` + strings.Repeat("A", 70<<10) + `"}}`))
	}))
	if _, err := mustTransit(
		t,
		"unix://"+sock,
		"k",
		1,
	).Sign(context.Background(), []byte("m")); err == nil {
		t.Error("oversized response: want error")
	}
}

func TestHeadersAreCopies(t *testing.T) {
	fb, _ := newFake(t)
	s := NewSigner(fb, agent, "K", func() time.Time { return time.Unix(1795425007, 0) })
	h1, _ := s.Headers(context.Background(), "example.com")
	h1[0].Value = "x"
	h2, _ := s.Headers(context.Background(), "example.com")
	if h2[0].Value == "x" {
		t.Error("cached slice was mutated through the returned one")
	}
}

// Guards: G5
func TestSignatureAuthority(t *testing.T) {
	for _, c := range []struct{ scheme, in, want string }{
		{"https", "A.Example.:443", "a.example."},
		{"https", "Example.com", "example.com"},
		{"http", "example.com:80", "example.com"},
		{"https", "example.com:80", "example.com:80"},
		{"http", "example.com:443", "example.com:443"},
		{"https", "a b.com", ""},
		{"https", "[2001:DB8::1]:443", "[2001:db8::1]"},
		{"http", "[2001:db8::1]:443", "[2001:db8::1]:443"},
		{"https", "[example.com]", ""},
		{"https", "", ""},
		{"https", ":443", ""},
		{"https", "bücher.de", ""},
		{"https", "a.example\n", ""},
	} {
		if got := SignatureAuthority(c.scheme, c.in); got != c.want {
			t.Errorf("%s %s: got %q, want %q", c.scheme, c.in, got, c.want)
		}
	}
}

func mustTransit(t *testing.T, address, key string, version int) *Transit {
	t.Helper()
	tr, err := NewTransit(address, "transit", key, version, "")
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func TestTransitHTTPMountAndToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/secret-transit/sign/k" || r.Header.Get("X-Vault-Token") != "s.token" {
			t.Errorf("path %q, token %q", r.URL.Path, r.Header.Get("X-Vault-Token"))
		}
		w.Write([]byte(`{"data":{"signature":"vault:v1:AA=="}}`))
	}))
	t.Cleanup(srv.Close)
	tr, err := NewTransit(srv.URL+"/", "/secret-transit/", "k", 1, "s.token")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Sign(context.Background(), []byte("m")); err != nil {
		t.Error(err)
	}
}

func TestTransitSendsNoTokenWhenEmpty(t *testing.T) {
	sock := unixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.Header["X-Vault-Token"]; ok {
			t.Error("X-Vault-Token sent without a token")
		}
		w.Write([]byte(`{"data":{"signature":"vault:v1:AA=="}}`))
	}))
	if _, err := mustTransit(
		t,
		"unix://"+sock,
		"k",
		1,
	).Sign(context.Background(), []byte("m")); err != nil {
		t.Error(err)
	}
}

// keyJSON is Transit's answer to a key read: one key version of type typ.
func keyJSON(typ string, version int, pub []byte) string {
	return fmt.Sprintf(`{"data":{"type":%q,"keys":{"%d":{"public_key":%q}}}}`,
		typ, version, base64.StdEncoding.EncodeToString(pub))
}

func TestTransitPublicKey(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/keys-mount/keys/web-bot-auth" ||
			r.Header.Get("X-Vault-Token") != "tok" {
			t.Errorf("bad request %s %s", r.Method, r.URL.Path)
		}
		w.Write([]byte(keyJSON("ed25519", 2, pub)))
	}))
	defer srv.Close()

	tr, err := NewTransit(srv.URL, "keys-mount", "web-bot-auth", 2, "tok")
	if err != nil {
		t.Fatal(err)
	}
	got, err := tr.PublicKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(pub) {
		t.Fatalf("PublicKey = %x, want %x", got, pub)
	}

	for name, body := range map[string]string{
		"missing version": keyJSON("ed25519", 1, pub),
		"wrong type":      keyJSON("rsa-2048", 2, pub),
		"short key":       keyJSON("ed25519", 2, pub[:3]),
	} {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Write([]byte(body))
		}))
		tr, _ := NewTransit(s.URL, "transit", "web-bot-auth", 2, "")
		if _, err := tr.PublicKey(context.Background()); err == nil {
			t.Errorf("%s: want error", name)
		}
		s.Close()
	}
}

// The token goes only to the configured address: a redirect isn't followed,
// and no proxy from the environment is used.
func TestTransitStaysOnItsAddress(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Errorf("redirect followed, token %q", r.Header.Get("X-Vault-Token"))
	}))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	t.Setenv("HTTP_PROXY", other.URL)
	t.Setenv("HTTPS_PROXY", other.URL)

	tr, err := NewTransit(srv.URL, "transit", "k", 1, "s.token")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tr.Sign(context.Background(), []byte("m")); err == nil {
		t.Error("Sign through a redirect: want error")
	}
	if _, err := tr.PublicKey(context.Background()); err == nil {
		t.Error("PublicKey through a redirect: want error")
	}
}
