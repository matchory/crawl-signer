package robots

import (
	"sync"
	"time"
)

// Pacer spaces the requests to each origin by its Crawl-delay. It keeps the
// time of the last request it let through per origin, apart from the
// robots.txt cache, so neither an origin dropped from the cache nor a request
// that came before robots.txt was fetched escapes it.
type Pacer struct {
	delay func(Origin) time.Duration
	max   time.Duration
	now   func() time.Time

	mu        sync.Mutex
	last      map[string]time.Time
	lastSweep time.Time
}

// NewPacer returns a Pacer that reads an origin's Crawl-delay from delay,
// such as Cache.Delay, and caps it at maxDelay.
func NewPacer(
	delay func(Origin) time.Duration,
	maxDelay time.Duration,
	now func() time.Time,
) *Pacer {
	return &Pacer{delay: delay, max: maxDelay, now: now, last: map[string]time.Time{}}
}

// Pace is called for each request robots.txt allows. If the origin's
// Crawl-delay has passed since the last request it let through, it records
// this one and returns zero; otherwise it returns how long until it has
// passed, and records nothing.
func (p *Pacer) Pace(o Origin) time.Duration {
	o, ok := canonical(o)
	if !ok {
		return 0
	}
	key := o.key()
	d := min(p.delay(o), p.max)
	now := p.now()

	p.mu.Lock()
	defer p.mu.Unlock()
	p.sweep(now)
	if last, ok := p.last[key]; ok && now.Before(last.Add(d)) {
		return last.Add(d).Sub(now)
	}
	p.last[key] = now
	return 0
}

// sweep forgets, at most once a second, the origins whose last request is
// at least the cap ago: no delay can refuse their next one.
func (p *Pacer) sweep(now time.Time) {
	if now.Sub(p.lastSweep) < time.Second {
		return
	}
	p.lastSweep = now
	for k, t := range p.last {
		if now.Sub(t) >= p.max {
			delete(p.last, k)
		}
	}
}
