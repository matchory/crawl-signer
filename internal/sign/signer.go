package sign

import (
	"context"
	"encoding/base64"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/matchory/crawl-signer/internal/config"
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

type entry struct {
	headers []rules.Header
	expires int64
}

// Signer caches one signature per authority; a signature is valid for 60 s.
type Signer struct {
	b   Backend
	cfg config.Config
	now func() time.Time

	mu        sync.Mutex
	cache     map[string]entry
	lastSweep int64
	group     singleflight.Group
}

func NewSigner(b Backend, cfg config.Config, now func() time.Time) *Signer {
	return &Signer{b: b, cfg: cfg, now: now, cache: map[string]entry{}}
}

// Headers returns Signature-Agent, Signature-Input and Signature for the
// canonical authority. If re-signing fails, a still-unexpired entry is served.
func (s *Signer) Headers(ctx context.Context, authority string) ([]rules.Header, error) {
	now := s.now().Unix()

	s.mu.Lock()
	if now != s.lastSweep {
		s.lastSweep = now
		for k, e := range s.cache {
			if now >= e.expires {
				delete(s.cache, k)
			}
		}
	}
	e, ok := s.cache[authority]
	s.mu.Unlock()
	if ok && now >= e.expires {
		ok = false
	}
	if ok && now < e.expires-refresh {
		return clone(e.headers), nil
	}

	v, err, _ := s.group.Do(authority, func() (any, error) {
		created := now - now%step
		expires := created + validity
		base, input := Base(authority, s.cfg.SignatureAgent, s.cfg.KeyID, created, expires)
		sig, err := s.b.Sign(context.WithoutCancel(ctx), []byte(base))
		if err != nil {
			return nil, err
		}
		ne := entry{expires: expires, headers: []rules.Header{
			{Name: "Signature-Agent", Value: `sig1="` + s.cfg.SignatureAgent + `"`},
			{Name: "Signature-Input", Value: input},
			{Name: "Signature", Value: "sig1=:" + base64.StdEncoding.EncodeToString(sig) + ":"},
		}}
		s.mu.Lock()
		s.cache[authority] = ne
		s.mu.Unlock()
		return ne, nil
	})
	if err != nil {
		if ok {
			return clone(e.headers), nil
		}
		return nil, err
	}
	return clone(v.(entry).headers), nil
}

func clone(h []rules.Header) []rules.Header { return append([]rules.Header(nil), h...) }
