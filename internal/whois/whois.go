// Package whois names the tailnet node behind a caller's address.
package whois

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"time"

	"tailscale.com/client/tailscale/apitype"
)

const ttl = 10 * time.Minute

// Caller is a tailnet node: its MagicDNS short name and its ACL tags.
type Caller struct {
	Node string
	Tags []string
}

// Source answers LocalAPI whois queries; *local.Client implements it.
type Source interface {
	WhoIs(ctx context.Context, addr string) (*apitype.WhoIsResponse, error)
}

type entry struct {
	caller  Caller
	expires time.Time
}

// Resolver caches successful lookups per address for 10 minutes.
type Resolver struct {
	src Source
	now func() time.Time

	mu    sync.Mutex
	cache map[netip.Addr]entry
}

func New(src Source, now func() time.Time) *Resolver {
	return &Resolver{src: src, now: now, cache: map[netip.Addr]entry{}}
}

func (r *Resolver) Lookup(ctx context.Context, a netip.Addr) (Caller, error) {
	r.mu.Lock()
	e, ok := r.cache[a]
	r.mu.Unlock()
	if ok && r.now().Before(e.expires) {
		return e.caller, nil
	}

	resp, err := r.src.WhoIs(ctx, a.String())
	if err != nil {
		return Caller{}, err
	}
	if resp == nil || resp.Node == nil {
		return Caller{}, errors.New("whois: no node in response")
	}
	name, _, _ := strings.Cut(strings.TrimSuffix(resp.Node.Name, "."), ".")
	c := Caller{Node: name, Tags: resp.Node.Tags}

	r.mu.Lock()
	r.cache[a] = entry{caller: c, expires: r.now().Add(ttl)}
	r.mu.Unlock()
	return c, nil
}
