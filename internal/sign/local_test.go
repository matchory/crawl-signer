package sign

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"
)

// The key from RFC 9421 appendix B.1.4, which the Web Bot Auth drafts use.
const (
	rfcPrivatePEM = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF
-----END PRIVATE KEY-----`
	rfcJWK = `{"kty":"OKP","crv":"Ed25519","d":"n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU",` +
		`"x":"JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"}`
	// The thumbprint the Web Bot Auth architecture draft gives for that key.
	rfcThumbprint = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"
)

func TestNewLocalKeyFormats(t *testing.T) {
	for name, in := range map[string]string{
		"PEM":                 rfcPrivatePEM,
		"PEM with whitespace": "\n  " + rfcPrivatePEM + "\n\n",
		"JWK":                 rfcJWK,
		"JWK without x":       `{"kty":"OKP","crv":"Ed25519","d":"n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU"}`,
	} {
		k, err := NewLocalKey([]byte(in))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got := Thumbprint(k.Public()); got != rfcThumbprint {
			t.Errorf("%s: thumbprint %q, want %q", name, got, rfcThumbprint)
		}
	}
}

func TestNewLocalKeyRefuses(t *testing.T) {
	_, rsaLike, _ := ed25519.GenerateKey(nil)
	der, _ := x509.MarshalPKCS8PrivateKey(rsaLike)
	pub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	for name, in := range map[string]string{
		"empty":          "",
		"garbage":        "not a key",
		"public PEM":     string(pub),
		"bad PKCS8":      "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----",
		"JWK wrong kty":  `{"kty":"EC","crv":"P-256","d":"AA"}`,
		"JWK short d":    `{"kty":"OKP","crv":"Ed25519","d":"AAAA"}`,
		"JWK x mismatch": strings.Replace(rfcJWK, `"x":"J`, `"x":"K`, 1),
		"JWK malformed":  `{"kty":`,
	} {
		if _, err := NewLocalKey([]byte(in)); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestLocalKeySigns(t *testing.T) {
	k, err := NewLocalKey([]byte(rfcPrivatePEM))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := k.Sign(context.Background(), []byte("msg"))
	if err != nil || !ed25519.Verify(k.Public(), []byte("msg"), sig) {
		t.Errorf("signature does not verify (%v)", err)
	}
	if x := base64.RawURLEncoding.EncodeToString(
		k.Public(),
	); x != "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs" {
		t.Errorf("public key %s", x)
	}
}
