package main

import (
	"testing"

	"github.com/matchory/crawl-signer/internal/config"
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
		_, got, err := signingBackend(config.SigningKey{
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
	_, _, err := signingBackend(config.SigningKey{
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
		if _, _, err := signingBackend(k); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestSigningBackendTransitKeepsKeyID(t *testing.T) {
	t.Setenv("CRAWL_SIGNER_TEST_TOKEN", "s.token\n")

	b, keyid, err := signingBackend(
		config.SigningKey{KeyID: "transit-kid", Transit: &config.Transit{
			Address: "https://openbao.example.com:8200", Mount: "transit", Key: "k", Version: 1,
			Token: &config.DataSource{EnvironmentVariable: "CRAWL_SIGNER_TEST_TOKEN"},
		}},
	)
	if err != nil || b == nil || keyid != "transit-kid" {
		t.Errorf("got %v, %q, %v", b, keyid, err)
	}
}
