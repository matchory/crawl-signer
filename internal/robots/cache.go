package robots

import (
	"container/list"
	"context"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/matchory/crawl-signer/internal/sign"
)

// Origin is the scheme and authority whose robots.txt governs a request.
type Origin struct {
	Scheme, Authority string
}

// Outcome is the robots.txt decision for one request.
type Outcome int

const (
	// Unavailable means no usable robots.txt copy exists; the caller must not crawl.
	Unavailable Outcome = iota
	Allowed
	Disallowed
)

func (o Outcome) String() string {
	switch o {
	case Allowed:
		return "allowed"
	case Disallowed:
		return "disallowed"
	}
	return "unavailable"
}

// Fetcher fetches an origin's robots.txt. An error means the origin was unreachable.
type Fetcher interface {
	Fetch(ctx context.Context, o Origin) (Result, error)
}

// Result is a fetched robots.txt response.
type Result struct {
	Status    int
	MaxAge    time.Duration
	HasMaxAge bool
	Body      []byte
}

const (
	minTTL       = time.Hour
	maxTTL       = 24 * time.Hour
	firstBackoff = 5 * time.Minute
	maxBackoff   = time.Hour
	// maxStale is how long a good copy keeps applying while refetches fail.
	maxStale     = 30 * 24 * time.Hour
	fetchTimeout = 30 * time.Second
)

// waitTimeout bounds how long Check waits for a fetch; a variable so tests can lower it.
var waitTimeout = 10 * time.Second

// TTL is how long a fetch result is used before the next fetch. failures is
// the number of consecutive failed fetches before this one.
func TTL(r Result, failures int) time.Duration {
	if r.Status >= 200 && r.Status < 300 {
		if !r.HasMaxAge {
			return maxTTL
		}
		return min(max(r.MaxAge, minTTL), maxTTL)
	}
	if usable(r.Status) {
		return maxTTL
	}
	d := firstBackoff
	for range failures {
		d *= 2
		if d >= maxBackoff {
			return maxBackoff
		}
	}
	return d
}

// usable reports whether a status yields rules: 2xx parses the body, other
// 4xx allow everything (RFC 9309 2.3.1.3). 429 is rate limiting, not absence.
func usable(status int) bool {
	return status >= 200 && status < 300 || status >= 400 && status < 500 && status != 429
}

type entry struct {
	key      string
	rules    Rules
	good     bool      // rules come from a 2xx fetch and may be used stale
	goodAt   time.Time // when rules were fetched
	allowAll bool      // a 4xx said "no robots.txt"; only valid until expires
	expires  time.Time
	failures int
	elem     *list.Element
}

// Cache holds each origin's rules in an LRU bounded by Rules.Size.
type Cache struct {
	f        Fetcher
	maxBytes int64
	now      func() time.Time
	group    singleflight.Group

	mu      sync.Mutex
	entries map[string]*entry
	lru     *list.List // front is most recently used
	bytes   int64
}

func NewCache(f Fetcher, maxBytes int64, now func() time.Time) *Cache {
	return &Cache{f: f, maxBytes: maxBytes, now: now, entries: map[string]*entry{}, lru: list.New()}
}

// Check decides whether robots.txt allows path on o.
func (c *Cache) Check(ctx context.Context, o Origin, path string) Outcome {
	if path == "/robots.txt" {
		return Allowed
	}
	scheme := strings.ToLower(o.Scheme)
	if scheme != "http" && scheme != "https" {
		return Unavailable
	}
	auth := sign.CanonicalAuthority(scheme, o.Authority)
	if auth == "" {
		return Unavailable
	}
	o = Origin{Scheme: scheme, Authority: auth}
	key := scheme + "://" + auth

	if e, ok := c.lookup(key); ok && c.now().Before(e.expires) {
		return c.decide(e, path)
	}

	ch := c.group.DoChan(key, func() (any, error) {
		// A flight that finished just before this one started has already refreshed the entry.
		if e, ok := c.lookup(key); ok && c.now().Before(e.expires) {
			return e, nil
		}
		fctx, cancel := context.WithTimeout(context.Background(), fetchTimeout)
		defer cancel()
		r, err := c.f.Fetch(fctx, o)
		return c.store(key, r, err), nil
	})
	timer := time.NewTimer(waitTimeout)
	defer timer.Stop()
	select {
	case res := <-ch:
		return c.decide(res.Val.(entry), path)
	case <-timer.C:
	case <-ctx.Done():
	}
	// The fetch carries on and fills the cache; meanwhile a stale copy beats none.
	if e, ok := c.lookup(key); ok {
		return c.decide(e, path)
	}
	return Unavailable
}

func (c *Cache) decide(e entry, path string) Outcome {
	if e.allowAll {
		return Allowed
	}
	if !e.good || c.now().Sub(e.goodAt) > maxStale {
		return Unavailable
	}
	if e.rules.Allowed(path) {
		return Allowed
	}
	return Disallowed
}

// lookup returns a copy of key's entry and marks it recently used.
func (c *Cache) lookup(key string) (entry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return entry{}, false
	}
	c.lru.MoveToFront(e.elem)
	return *e, true
}

// store folds a fetch result into key's entry and returns a copy of it.
func (c *Cache) store(key string, r Result, err error) entry {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		e = &entry{key: key}
		e.elem = c.lru.PushFront(e)
		c.entries[key] = e
	} else {
		c.lru.MoveToFront(e.elem)
		c.bytes -= int64(e.rules.Size())
	}
	switch {
	case err == nil && r.Status >= 200 && r.Status < 300:
		e.rules, e.good, e.goodAt, e.allowAll, e.failures = Parse(r.Body, Agent), true, now, false, 0
		e.expires = now.Add(TTL(r, 0))
	case err == nil && usable(r.Status):
		e.rules, e.good, e.allowAll, e.failures = Rules{}, false, true, 0
		e.expires = now.Add(TTL(r, 0))
	default:
		e.allowAll = false
		if err != nil {
			r = Result{}
		}
		e.expires = now.Add(TTL(r, e.failures))
		e.failures++
	}
	c.bytes += int64(e.rules.Size())
	for c.bytes > c.maxBytes && c.lru.Back() != e.elem {
		old := c.lru.Remove(c.lru.Back()).(*entry)
		delete(c.entries, old.key)
		c.bytes -= int64(old.rules.Size())
	}
	return *e
}
