package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/matchory/crawl-signer/internal/config"
	"github.com/matchory/crawl-signer/internal/sign"
)

// The key from RFC 9421 appendix B.1.4 and its RFC 7638 thumbprint.
const (
	testKey = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF
-----END PRIVATE KEY-----`
	testKeyID = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"
)

func TestSigningBackendComputesKeyID(t *testing.T) {
	t.Setenv("CRAWL_SIGNER_TEST_KEY", testKey)

	for _, keyid := range []string{"", testKeyID} {
		_, _, got, err := signingBackend(context.Background(), config.SigningKey{
			KeyID:      keyid,
			PrivateKey: &config.DataSource{EnvironmentVariable: "CRAWL_SIGNER_TEST_KEY"},
		})
		if err != nil || got != testKeyID {
			t.Errorf("configured keyid %q: got %q, %v", keyid, got, err)
		}
	}
}

// Guards: G5
func TestSigningBackendRefusesAMismatchedKeyID(t *testing.T) {
	_, _, _, err := signingBackend(context.Background(), config.SigningKey{
		KeyID:      "not-the-thumbprint",
		PrivateKey: &config.DataSource{InlineString: testKey},
	})
	if err == nil {
		t.Error("a keyid that is not the key's thumbprint: want error")
	}
}

func TestSigningBackendErrors(t *testing.T) {
	for name, k := range map[string]config.SigningKey{
		"unreadable key": {PrivateKey: &config.DataSource{Filename: t.TempDir() + "/missing"}},
		"not a key":      {PrivateKey: &config.DataSource{InlineString: "nope"}},
		"unset token": {KeyID: "k", Transit: &config.Transit{
			Address: "unix:///run/bao.sock", Key: "k", Version: 1,
			Token: &config.DataSource{EnvironmentVariable: "CRAWL_SIGNER_TEST_UNSET"},
		}},
	} {
		if _, _, _, err := signingBackend(context.Background(), k); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

// transitServer answers a key read with pub as version 1.
func transitServer(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/transit/keys/k" || r.Header.Get("X-Vault-Token") != "s.token" {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		w.Write([]byte(`{"data":{"type":"ed25519","keys":{"1":{"public_key":"` +
			base64.StdEncoding.EncodeToString(pub) + `"}}}}`))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func transitKey(address, keyid string) config.SigningKey {
	return config.SigningKey{KeyID: keyid, Transit: &config.Transit{
		Address: address, Mount: "transit", Key: "k", Version: 1,
		Token: &config.DataSource{EnvironmentVariable: "CRAWL_SIGNER_TEST_TOKEN"},
	}}
}

func TestSigningBackendTransit(t *testing.T) {
	t.Setenv("CRAWL_SIGNER_TEST_TOKEN", "s.token\n")
	pub, _, _ := ed25519.GenerateKey(nil)
	keyid := sign.Thumbprint(pub)

	b, got, gotID, err := signingBackend(
		context.Background(),
		transitKey(transitServer(t, pub), keyid),
	)
	if err != nil || b == nil || !got.Equal(pub) || gotID != keyid {
		t.Errorf("got %v, %x, %q, %v", b, got, gotID, err)
	}
}

// Guards: G5
func TestSigningBackendRefusesAMismatchedTransitKeyID(t *testing.T) {
	t.Setenv("CRAWL_SIGNER_TEST_TOKEN", "s.token")
	pub, _, _ := ed25519.GenerateKey(nil)

	if _, _, _, err := signingBackend(
		context.Background(),
		transitKey(transitServer(t, pub), "other"),
	); err == nil {
		t.Error("a keyid that is not the Transit key's thumbprint: want error")
	}
}

func TestSigningBackendTransitUnreachable(t *testing.T) {
	t.Setenv("CRAWL_SIGNER_TEST_TOKEN", "s.token")
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close()

	if _, _, _, err := signingBackend(context.Background(), transitKey(srv.URL, "k")); err == nil {
		t.Error("Transit unreachable: want error")
	}
}
