package robots

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)} }

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// fakeFetcher answers from fn and counts fetches per origin.
type fakeFetcher struct {
	mu    sync.Mutex
	calls map[Origin]int
	fn    func(Origin) (Result, error)
}

func newFake(fn func(Origin) (Result, error)) *fakeFetcher {
	return &fakeFetcher{calls: map[Origin]int{}, fn: fn}
}

func (f *fakeFetcher) Fetch(_ context.Context, o Origin) (Result, error) {
	f.mu.Lock()
	f.calls[o]++
	fn := f.fn
	f.mu.Unlock()
	return fn(o)
}

func (f *fakeFetcher) count(o Origin) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[o]
}

func (f *fakeFetcher) set(fn func(Origin) (Result, error)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fn = fn
}

func body(s string) func(Origin) (Result, error) {
	return func(Origin) (Result, error) { return Result{Status: 200, Body: []byte(s)}, nil }
}

var example = Origin{Scheme: "https", Authority: "example.com"}

func TestTTL(t *testing.T) {
	for _, c := range []struct {
		name     string
		r        Result
		failures int
		want     time.Duration
	}{
		{"200 without max-age", Result{Status: 200}, 0, 24 * time.Hour},
		{"max-age=0 is raised to the floor", Result{Status: 200, HasMaxAge: true}, 0, time.Hour},
		{"max-age above the cap", Result{Status: 200, HasMaxAge: true, MaxAge: 172800 * time.Second}, 0, 24 * time.Hour},
		{"max-age within bounds", Result{Status: 200, HasMaxAge: true, MaxAge: 2 * time.Hour}, 0, 2 * time.Hour},
		{"404", Result{Status: 404}, 0, 24 * time.Hour},
		{"404 ignores max-age", Result{Status: 404, HasMaxAge: true, MaxAge: time.Hour}, 0, 24 * time.Hour},
		{"5xx first failure", Result{Status: 503}, 0, 5 * time.Minute},
		{"5xx second failure", Result{Status: 503}, 1, 10 * time.Minute},
		{"5xx third failure", Result{Status: 503}, 2, 20 * time.Minute},
		{"5xx capped", Result{Status: 503}, 5, time.Hour},
		{"unreachable", Result{}, 0, 5 * time.Minute},
		{"429 backs off", Result{Status: 429}, 1, 10 * time.Minute},
	} {
		if got := TTL(c.r, c.failures); got != c.want {
			t.Errorf("%s: TTL = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestNotFoundAllows(t *testing.T) {
	clk := newClock()
	f := newFake(func(Origin) (Result, error) {
		return Result{Status: 404, Body: []byte("User-agent: *\nDisallow: /")}, nil
	})
	c := NewCache(f, 1<<20, clk.now)
	if got := c.Check(context.Background(), example, "/a"); got != Allowed {
		t.Fatalf("Check after 404 = %v, want Allowed", got)
	}
	clk.advance(23 * time.Hour)
	c.Check(context.Background(), example, "/a")
	if n := f.count(example); n != 1 {
		t.Fatalf("fetches within 24 h = %d, want 1", n)
	}
	clk.advance(2 * time.Hour)
	c.Check(context.Background(), example, "/a")
	if n := f.count(example); n != 2 {
		t.Fatalf("fetches after 25 h = %d, want 2", n)
	}
}

func TestStaleOnError(t *testing.T) {
	clk := newClock()
	f := newFake(body("User-agent: MatchoryBot\nDisallow: /x\n"))
	c := NewCache(f, 1<<20, clk.now)
	ctx := context.Background()
	if got := c.Check(ctx, example, "/x"); got != Disallowed {
		t.Fatalf("fresh: Check(/x) = %v, want Disallowed", got)
	}

	f.set(func(Origin) (Result, error) { return Result{Status: 503}, nil })
	clk.advance(10 * 24 * time.Hour)
	if got := c.Check(ctx, example, "/x"); got != Disallowed {
		t.Fatalf("10 days, 503: Check(/x) = %v, want Disallowed", got)
	}
	if got := c.Check(ctx, example, "/a"); got != Allowed {
		t.Fatalf("10 days, 503: Check(/a) = %v, want Allowed", got)
	}

	f.set(func(Origin) (Result, error) { return Result{}, errors.New("unreachable") })
	clk.advance(21 * 24 * time.Hour)
	if got := c.Check(ctx, example, "/a"); got != Unavailable {
		t.Fatalf("31 days: Check(/a) = %v, want Unavailable", got)
	}
}

func TestNotFoundIsNoStaleFallback(t *testing.T) {
	for _, first := range []string{"404 first", "200 then 404"} {
		t.Run(first, func(t *testing.T) {
			clk := newClock()
			f := newFake(body("User-agent: *\nDisallow: /x\n"))
			c := NewCache(f, 1<<20, clk.now)
			ctx := context.Background()
			if first == "200 then 404" {
				c.Check(ctx, example, "/a")
				clk.advance(25 * time.Hour)
			}
			f.set(func(Origin) (Result, error) { return Result{Status: 404}, nil })
			if got := c.Check(ctx, example, "/x"); got != Allowed {
				t.Fatalf("after 404: %v, want Allowed", got)
			}
			f.set(func(Origin) (Result, error) { return Result{Status: 503}, nil })
			clk.advance(25 * time.Hour)
			if got := c.Check(ctx, example, "/a"); got != Unavailable {
				t.Fatalf("503 after 404: %v, want Unavailable", got)
			}
		})
	}
}

func TestExpiredNotFoundOnWaitTimeout(t *testing.T) {
	old := waitTimeout
	waitTimeout = 50 * time.Millisecond
	t.Cleanup(func() { waitTimeout = old })

	clk := newClock()
	f := newFake(func(Origin) (Result, error) { return Result{Status: 404}, nil })
	c := NewCache(f, 1<<20, clk.now)
	ctx := context.Background()
	if got := c.Check(ctx, example, "/a"); got != Allowed {
		t.Fatalf("after 404: %v, want Allowed", got)
	}
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	f.set(func(Origin) (Result, error) {
		<-release
		return Result{Status: 404}, nil
	})
	clk.advance(25 * time.Hour)
	if got := c.Check(ctx, example, "/a"); got != Unavailable {
		t.Fatalf("expired 404, refetch timed out: %v, want Unavailable", got)
	}
}

func TestFailureBackoff(t *testing.T) {
	clk := newClock()
	f := newFake(func(Origin) (Result, error) { return Result{Status: 500}, nil })
	c := NewCache(f, 1<<20, clk.now)
	ctx := context.Background()
	if got := c.Check(ctx, example, "/"); got != Unavailable {
		t.Fatalf("cold 500: %v, want Unavailable", got)
	}
	clk.advance(4 * time.Minute)
	c.Check(ctx, example, "/")
	if n := f.count(example); n != 1 {
		t.Fatalf("fetches within backoff = %d, want 1", n)
	}
	clk.advance(2 * time.Minute) // 6 min: first 5 min backoff over
	c.Check(ctx, example, "/")
	clk.advance(9 * time.Minute) // second backoff is 10 min
	c.Check(ctx, example, "/")
	if n := f.count(example); n != 2 {
		t.Fatalf("fetches = %d, want 2", n)
	}

	f.set(body(""))
	clk.advance(2 * time.Minute)
	if got := c.Check(ctx, example, "/"); got != Allowed {
		t.Fatalf("after recovery: %v, want Allowed", got)
	}
	f.set(func(Origin) (Result, error) { return Result{Status: 500}, nil })
	clk.advance(25 * time.Hour)
	c.Check(ctx, example, "/")
	clk.advance(6 * time.Minute) // failures reset on success: back to 5 min
	c.Check(ctx, example, "/")
	if n := f.count(example); n != 5 {
		t.Fatalf("fetches = %d, want 5", n)
	}
}

func TestSingleflight(t *testing.T) {
	release := make(chan struct{})
	f := newFake(func(Origin) (Result, error) {
		<-release
		return Result{Status: 200}, nil
	})
	c := NewCache(f, 1<<20, newClock().now)
	var wg, started sync.WaitGroup
	var allowed atomic.Int32
	for range 50 {
		started.Add(1)
		wg.Go(func() {
			started.Done()
			if c.Check(context.Background(), example, "/a") == Allowed {
				allowed.Add(1)
			}
		})
	}
	started.Wait()
	close(release)
	wg.Wait()
	if n := f.count(example); n != 1 {
		t.Fatalf("fetches = %d, want 1", n)
	}
	if allowed.Load() != 50 {
		t.Fatalf("allowed = %d, want 50", allowed.Load())
	}
}

func TestWaitTimeout(t *testing.T) {
	old := waitTimeout
	waitTimeout = 100 * time.Millisecond // stands in for 10 s; the fetcher stands in for 11 s
	t.Cleanup(func() { waitTimeout = old })

	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	f := newFake(func(Origin) (Result, error) {
		<-release
		return Result{Status: 200}, nil
	})
	c := NewCache(f, 1<<20, newClock().now)
	start := time.Now()
	got := c.Check(context.Background(), example, "/a")
	elapsed := time.Since(start)
	if got != Unavailable {
		t.Fatalf("Check = %v, want Unavailable", got)
	}
	if elapsed < waitTimeout || elapsed > 10*waitTimeout {
		t.Fatalf("returned after %v, want about %v", elapsed, waitTimeout)
	}
}

func TestCallerContextCancels(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	f := newFake(func(Origin) (Result, error) {
		<-release
		return Result{Status: 200}, nil
	})
	c := NewCache(f, 1<<20, newClock().now)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := c.Check(ctx, example, "/a"); got != Unavailable {
		t.Fatalf("Check = %v, want Unavailable", got)
	}
}

func TestEviction(t *testing.T) {
	const robots = "User-agent: *\nDisallow: /x\n"
	f := newFake(body(robots))
	size := Parse([]byte(robots), Agent).Size()
	c := NewCache(f, int64(3*size), newClock().now)
	ctx := context.Background()
	o := func(h string) Origin { return Origin{Scheme: "https", Authority: h} }

	for _, h := range []string{"a.com", "b.com", "c.com"} {
		c.Check(ctx, o(h), "/")
	}
	c.Check(ctx, o("a.com"), "/") // a is now more recent than b
	c.Check(ctx, o("d.com"), "/") // evicts b
	for _, h := range []string{"a.com", "c.com", "d.com", "b.com"} {
		c.Check(ctx, o(h), "/")
	}
	for h, want := range map[string]int{"a.com": 1, "c.com": 1, "d.com": 1, "b.com": 2} {
		if n := f.count(o(h)); n != want {
			t.Errorf("fetches for %s = %d, want %d", h, n, want)
		}
	}
}

func TestRobotsPathExempt(t *testing.T) {
	f := newFake(func(Origin) (Result, error) { return Result{}, errors.New("must not fetch") })
	c := NewCache(f, 1<<20, newClock().now)
	if got := c.Check(context.Background(), example, "/robots.txt"); got != Allowed {
		t.Fatalf("Check(/robots.txt) = %v, want Allowed", got)
	}
	if n := f.count(example); n != 0 {
		t.Fatalf("fetches = %d, want 0", n)
	}
}

func TestCheckCanonicalisesOrigin(t *testing.T) {
	f := newFake(body("User-agent: *\nDisallow: /x\n"))
	c := NewCache(f, 1<<20, newClock().now)
	ctx := context.Background()
	c.Check(ctx, Origin{Scheme: "HTTPS", Authority: "Example.COM:443"}, "/")
	c.Check(ctx, example, "/")
	if n := f.count(example); n != 1 {
		t.Fatalf("fetches for canonical origin = %d, want 1 (calls: %v)", n, f.calls)
	}
	if got := c.Check(ctx, Origin{Scheme: "https", Authority: "a b.com"}, "/"); got != Unavailable {
		t.Fatalf("invalid authority: %v, want Unavailable", got)
	}
	if got := c.Check(ctx, Origin{Scheme: "ftp", Authority: "example.com"}, "/"); got != Unavailable {
		t.Fatalf("ftp scheme: %v, want Unavailable", got)
	}
}

func TestLookupHookAndStats(t *testing.T) {
	const robots = "User-agent: *\nDisallow: /x\n"
	clk := newClock()
	c := NewCache(newFake(body(robots)), 1<<20, clk.now)
	var hits, misses int
	c.OnLookup = func(hit bool) {
		if hit {
			hits++
		} else {
			misses++
		}
	}
	ctx := context.Background()
	c.Check(ctx, example, "/")
	c.Check(ctx, example, "/x")
	c.Check(ctx, example, "/robots.txt")
	clk.advance(25 * time.Hour)
	c.Check(ctx, example, "/")
	if hits != 1 || misses != 2 {
		t.Errorf("hits %d misses %d, want 1 and 2", hits, misses)
	}
	entries, bytes := c.Stats()
	if entries != 1 || bytes != int64(Parse([]byte(robots), Agent).Size()) {
		t.Errorf("stats: %d entries, %d bytes", entries, bytes)
	}
}
