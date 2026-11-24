package sign

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/matchory/crawl-signer/internal/config"
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
	} {
		if got := CanonicalAuthority(c.scheme, c.in); got != c.want {
			t.Errorf("%s %s: got %q, want %q", c.scheme, c.in, got, c.want)
		}
	}
}

const wantBase = `"@authority": example.com
"signature-agent";key="sig1": "https://crawler.matchory.net"
"@signature-params": ("@authority" "signature-agent";key="sig1");created=1795425000;expires=1795425060;keyid="K";alg="ed25519";tag="web-bot-auth"`

func TestBase(t *testing.T) {
	base, input := Base("example.com", "https://crawler.matchory.net", "K", 1795425000, 1795425060)
	if base != wantBase {
		t.Errorf("base:\n%s\nwant:\n%s", base, wantBase)
	}
	_, params, _ := strings.Cut(wantBase, `"@signature-params": `)
	if input != "sig1="+params {
		t.Errorf("input: got %q", input)
	}
}

type fakeBackend struct {
	priv  ed25519.PrivateKey
	calls atomic.Int32
	gate  chan struct{}
	err   error
}

func (f *fakeBackend) Sign(ctx context.Context, msg []byte) ([]byte, error) {
	f.calls.Add(1)
	if f.gate != nil {
		<-f.gate
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

var cfg = config.Config{KeyID: "K", SignatureAgent: "https://crawler.matchory.net"}

func hmap(hs []rules.Header) map[string]string {
	m := map[string]string{}
	for _, h := range hs {
		m[h.Name] = h.Value
	}
	return m
}

func TestSignatureVerifies(t *testing.T) {
	fb, pub := newFake(t)
	now := time.Unix(1795425007, 0)
	s := NewSigner(fb, cfg, func() time.Time { return now })
	hs, err := s.Headers(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	m := hmap(hs)
	if m["Signature-Agent"] != `sig1="https://crawler.matchory.net"` {
		t.Errorf("Signature-Agent: %q", m["Signature-Agent"])
	}
	base, input := Base("example.com", cfg.SignatureAgent, "K", 1795425000, 1795425060)
	if m["Signature-Input"] != input {
		t.Errorf("Signature-Input: %q, want %q", m["Signature-Input"], input)
	}
	v := strings.TrimSuffix(strings.TrimPrefix(m["Signature"], "sig1=:"), ":")
	sig, err := base64.StdEncoding.DecodeString(v)
	if err != nil || !ed25519.Verify(pub, []byte(base), sig) {
		t.Errorf("signature does not verify: %q (%v)", m["Signature"], err)
	}
}

func TestWindowCache(t *testing.T) {
	fb, _ := newFake(t)
	now := time.Unix(1795425007, 0)
	s := NewSigner(fb, cfg, func() time.Time { return now })
	ctx := context.Background()
	h1, _ := s.Headers(ctx, "example.com")
	h2, _ := s.Headers(ctx, "example.com")
	if fb.calls.Load() != 1 {
		t.Fatalf("calls = %d, want 1", fb.calls.Load())
	}
	if !strings.Contains(hmap(h1)["Signature-Input"], "created=1795425000;") || hmap(h1)["Signature"] != hmap(h2)["Signature"] {
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
	if in := hmap(h3)["Signature-Input"]; !strings.Contains(in, "created=1795425030;expires=1795425090;") {
		t.Errorf("re-sign window: %q", in)
	}
}

func TestTransitDown(t *testing.T) {
	fb, _ := newFake(t)
	now := time.Unix(1795425007, 0)
	s := NewSigner(fb, cfg, func() time.Time { return now })
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
	sock := filepath.Join(t.TempDir(), "bao.sock")
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
		w.Write([]byte(`{"data":{"signature":"vault:v3:` + base64.StdEncoding.EncodeToString([]byte("sigbytes")) + `"}}`))
	}))
	got, err := NewTransit(sock, "web-bot-auth", 3).Sign(context.Background(), []byte("msg"))
	if err != nil || string(got) != "sigbytes" {
		t.Errorf("got %q, %v", got, err)
	}
}

func TestTransitStatusError(t *testing.T) {
	sock := unixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "secret-detail", 503)
	}))
	_, err := NewTransit(sock, "k", 1).Sign(context.Background(), []byte("m"))
	if err == nil || !strings.Contains(err.Error(), "503") || strings.Contains(err.Error(), "secret-detail") {
		t.Errorf("err = %v", err)
	}
}

func TestTransitTimeout(t *testing.T) {
	sock := unixServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
	}))
	start := time.Now()
	_, err := NewTransit(sock, "k", 1).Sign(context.Background(), []byte("m"))
	if err == nil || time.Since(start) > 4*time.Second {
		t.Errorf("err = %v after %v, want timeout near 2s", err, time.Since(start))
	}
}

func TestConcurrentMissesShareOneCall(t *testing.T) {
	fb, _ := newFake(t)
	fb.gate = make(chan struct{})
	s := NewSigner(fb, cfg, func() time.Time { return time.Unix(1795425007, 0) })
	ctx1, cancel1 := context.WithCancel(context.Background())
	errs := make(chan error, 8)
	call := func(ctx context.Context) {
		_, err := s.Headers(ctx, "example.com")
		errs <- err
	}
	go call(ctx1)
	for fb.calls.Load() < 1 {
		time.Sleep(time.Millisecond)
	}
	for i := 0; i < 7; i++ {
		go call(context.Background())
	}
	time.Sleep(50 * time.Millisecond)
	cancel1()
	close(fb.gate)
	for i := 0; i < 8; i++ {
		if err := <-errs; err != nil {
			t.Errorf("caller %d: %v", i, err)
		}
	}
	if n := fb.calls.Load(); n != 1 {
		t.Errorf("calls = %d, want 1", n)
	}
}

func TestHeadersAreCopies(t *testing.T) {
	fb, _ := newFake(t)
	s := NewSigner(fb, cfg, func() time.Time { return time.Unix(1795425007, 0) })
	h1, _ := s.Headers(context.Background(), "example.com")
	h1[0].Value = "x"
	h2, _ := s.Headers(context.Background(), "example.com")
	if h2[0].Value == "x" {
		t.Error("cached slice was mutated through the returned one")
	}
}
