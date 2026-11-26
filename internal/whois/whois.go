// Package whois names the tailnet node behind a caller's address.
package whois

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
	"tailscale.com/client/tailscale/apitype"
)

// timeout bounds one LocalAPI query; a variable so tests can lower it.
var timeout = 2 * time.Second

const (
	ttl = 10 * time.Minute
	// failTTL keeps a down tailscaled from costing every request a timeout.
	failTTL = 5 * time.Second
)

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
	err     error
	expires time.Time
}

// Resolver caches lookups per address: 10 minutes, failures 5 seconds.
type Resolver struct {
	src Source
	now func() time.Time

	group singleflight.Group
	mu    sync.Mutex
	cache map[netip.Addr]entry
}

// New returns a Resolver that asks src.
func New(src Source, now func() time.Time) *Resolver {
	return &Resolver{src: src, now: now, cache: map[netip.Addr]entry{}}
}

// Lookup waits for the query at most as long as ctx allows. The query itself
// runs on its own timeout, so only tailscaled's failures are cached, never
// the caller giving up.
func (r *Resolver) Lookup(ctx context.Context, a netip.Addr) (Caller, error) {
	r.mu.Lock()
	e, ok := r.cache[a]
	r.mu.Unlock()
	if ok && r.now().Before(e.expires) {
		return e.caller, e.err
	}

	ch := r.group.DoChan(a.String(), func() (any, error) {
		qctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
		defer cancel()
		c, err := r.query(qctx, a)
		e := entry{caller: c, err: err, expires: r.now().Add(ttl)}
		if err != nil {
			e.expires = r.now().Add(failTTL)
		}
		r.mu.Lock()
		r.cache[a] = e
		r.mu.Unlock()
		return c, err
	})
	select {
	case res := <-ch:
		c, _ := res.Val.(Caller)

		return c, res.Err
	case <-ctx.Done():
		return Caller{}, ctx.Err()
	}
}

func (r *Resolver) query(ctx context.Context, a netip.Addr) (Caller, error) {
	resp, err := r.src.WhoIs(ctx, a.String())
	if err != nil {
		return Caller{}, err
	}
	if resp == nil || resp.Node == nil {
		return Caller{}, errors.New("whois: no node in response")
	}
	name, _, _ := strings.Cut(strings.TrimSuffix(resp.Node.Name, "."), ".")
	if name == "" {
		name = "unknown"
	}
	return Caller{Node: name, Tags: resp.Node.Tags}, nil
}
