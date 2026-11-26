package sign

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
)

// LocalKey signs with an Ed25519 private key held in memory.
type LocalKey struct {
	key ed25519.PrivateKey
}

// NewLocalKey parses an Ed25519 private key: PEM-encoded PKCS #8, as
// "openssl genpkey -algorithm ed25519" writes it, or a JWK with kty "OKP",
// crv "Ed25519" and the private part d.
func NewLocalKey(b []byte) (*LocalKey, error) {
	b = bytes.TrimSpace(b)
	if bytes.HasPrefix(b, []byte("{")) {
		return parseJWK(b)
	}

	block, _ := pem.Decode(b)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("signing key: neither a JWK nor a PEM \"PRIVATE KEY\" block")
	}

	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("signing key: %w", err)
	}

	priv, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("signing key: a %T, not an Ed25519 key", k)
	}

	return &LocalKey{key: priv}, nil
}

func parseJWK(b []byte) (*LocalKey, error) {
	var jwk struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		D   string `json:"d"`
		X   string `json:"x"`
	}
	if err := json.Unmarshal(b, &jwk); err != nil {
		return nil, fmt.Errorf("signing key: JWK: %w", err)
	}

	if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" {
		return nil, fmt.Errorf(
			"signing key: JWK is kty %q crv %q, not OKP Ed25519",
			jwk.Kty,
			jwk.Crv,
		)
	}

	seed, err := base64.RawURLEncoding.DecodeString(jwk.D)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("signing key: JWK has no valid private part d")
	}

	l := &LocalKey{key: ed25519.NewKeyFromSeed(seed)}
	if jwk.X != "" && jwk.X != base64.RawURLEncoding.EncodeToString(l.Public()) {
		return nil, errors.New("signing key: JWK's x is not the public key of its d")
	}

	return l, nil
}

// Sign implements Backend. It never fails.
func (l *LocalKey) Sign(_ context.Context, msg []byte) ([]byte, error) {
	return ed25519.Sign(l.key, msg), nil
}

// Public returns the public key.
func (l *LocalKey) Public() ed25519.PublicKey {
	pub, _ := l.key.Public().(ed25519.PublicKey)

	return pub
}

// Thumbprint is the RFC 7638 JWK thumbprint of an Ed25519 public key, which
// Web Bot Auth uses as the keyid.
func Thumbprint(pub ed25519.PublicKey) string {
	// RFC 7638 section 3.2: the required members in lexicographic order,
	// without whitespace.
	canonical := `{"crv":"Ed25519","kty":"OKP","x":"` + base64.RawURLEncoding.EncodeToString(
		pub,
	) + `"}`
	sum := sha256.Sum256([]byte(canonical))

	return base64.RawURLEncoding.EncodeToString(sum[:])
}
