package sign

import (
	"context"
	"encoding/base64"
	"errors"
	"time"

	"github.com/matchory/crawl-signer/internal/rules"
)

const (
	step     = 30 // created is aligned to this many seconds
	validity = 60 // seconds a signature stays valid
	refresh  = 10 // re-sign this many seconds before expiry
)

// Backend signs a message with the Ed25519 key.
type Backend interface {
	Sign(ctx context.Context, msg []byte) ([]byte, error)
}

// Signer caches one signature per authority; a signature is valid for 60 s.
type Signer struct {
	b     Backend
	agent Agent
	keyid string
	now   func() time.Time
	w     *Window[[]rules.Header]
}

// NewSigner returns a Signer that signs with b as the Signature-Agent agent,
// naming the key keyid.
func NewSigner(b Backend, agent Agent, keyid string, now func() time.Time) *Signer {
	return &Signer{
		b:     b,
		agent: agent,
		keyid: keyid,
		now:   now,
		w:     NewWindow[[]rules.Header](refresh),
	}
}

// Headers returns Signature-Agent, Signature-Input and Signature for the
// canonical authority. If re-signing fails, a still-unexpired entry is served.
func (s *Signer) Headers(ctx context.Context, authority string) ([]rules.Header, error) {
	if CanonicalAuthority("", authority) == "" {
		return nil, errors.New("sign: invalid authority")
	}
	now := s.now().Unix()

	h, err := s.w.Get(authority, now, func() ([]rules.Header, int64, error) {
		created := now - now%step
		expires := created + validity
		base, input := Base(authority, s.agent, s.keyid, created, expires)
		sig, err := s.b.Sign(context.WithoutCancel(ctx), []byte(base))
		if err != nil {
			return nil, 0, err
		}
		return []rules.Header{
			{Name: "Signature-Agent", Value: s.agent.Header()},
			{Name: "Signature-Input", Value: input},
			{Name: "Signature", Value: "sig1=:" + base64.StdEncoding.EncodeToString(sig) + ":"},
		}, expires, nil
	})
	if err != nil {
		return nil, err
	}

	return clone(h), nil
}

func clone(h []rules.Header) []rules.Header { return append([]rules.Header(nil), h...) }
