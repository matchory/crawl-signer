package robots

import (
	"context"
	"testing"
	"time"
)

// newPaced returns a cache serving robots.txt bodies by host, and a Pacer
// reading its delays with a 1-minute cap.
func newPaced(t *testing.T, bodies map[string]string, maxBytes int64) (*Cache, *Pacer, *clock) {
	t.Helper()
	clk := newClock()
	f := newFake(func(o Origin) (Result, error) {
		return Result{Status: 200, Body: []byte(bodies[o.Authority])}, nil
	})
	c := NewCache(f, agent, maxBytes, clk.now)
	return c, NewPacer(c.Delay, time.Minute, clk.now), clk
}

// Guards: G8
func TestPace(t *testing.T) {
	c, p, clk := newPaced(
		t,
		map[string]string{"example.com": "User-agent: *\nCrawl-delay: 10\n"},
		1<<20,
	)
	ctx := context.Background()

	if got := c.Check(ctx, example, "/a"); got != Allowed {
		t.Fatalf("Check = %v, want Allowed", got)
	}
	if w := p.Pace(example); w != 0 {
		t.Fatalf("first Pace = %v, want 0", w)
	}
	clk.advance(4 * time.Second)
	if w := p.Pace(example); w != 6*time.Second {
		t.Fatalf("Pace 4s later = %v, want 6s", w)
	}
	// A refused request takes no slot, so asking again doesn't push the next one back.
	clk.advance(5 * time.Second)
	if w := p.Pace(example); w != time.Second {
		t.Fatalf("Pace 9s later = %v, want 1s", w)
	}
	clk.advance(time.Second)
	if w := p.Pace(example); w != 0 {
		t.Fatalf("Pace 10s later = %v, want 0", w)
	}
	if w := p.Pace(Origin{Scheme: "HTTPS", Authority: "Example.COM:443"}); w != 10*time.Second {
		t.Fatalf("Pace for the same origin, spelled differently = %v, want 10s", w)
	}
	other := Origin{Scheme: "https", Authority: "other.example"}
	c.Check(ctx, other, "/a")
	if w := p.Pace(other); w != 0 {
		t.Fatalf("Pace for another origin = %v, want 0", w)
	}
}

// Guards: G8
func TestPaceCap(t *testing.T) {
	c, p, _ := newPaced(
		t,
		map[string]string{"example.com": "User-agent: *\nCrawl-delay: 3600\n"},
		1<<20,
	)
	c.Check(context.Background(), example, "/a")
	p.Pace(example)
	if w := p.Pace(example); w != time.Minute {
		t.Fatalf("Pace = %v, want the 1m cap", w)
	}
}

func TestPaceWithoutDelay(t *testing.T) {
	c, p, _ := newPaced(t, map[string]string{"example.com": "User-agent: *\nDisallow: /x\n"}, 1<<20)
	c.Check(context.Background(), example, "/a")
	for range 3 {
		if w := p.Pace(example); w != 0 {
			t.Fatalf("Pace = %v, want 0", w)
		}
	}
}

// Guards: G8
//
// A caller's first request to an origin, for /robots.txt, goes before
// robots.txt is fetched, so its delay isn't known yet. It still counts.
func TestPaceRobotsTxtFirst(t *testing.T) {
	c, p, _ := newPaced(
		t,
		map[string]string{"example.com": "User-agent: *\nCrawl-delay: 10\n"},
		1<<20,
	)
	ctx := context.Background()

	if got := c.Check(ctx, example, "/robots.txt"); got != Allowed {
		t.Fatalf("Check(/robots.txt) = %v", got)
	}
	if w := p.Pace(example); w != 0 {
		t.Fatalf("Pace for the first request = %v, want 0", w)
	}
	c.Check(ctx, example, "/a")
	if w := p.Pace(example); w != 10*time.Second {
		t.Fatalf("Pace right after /robots.txt = %v, want 10s", w)
	}
}

// Guards: G8
//
// An origin dropped from the robots.txt cache keeps its pacing.
func TestPaceSurvivesEviction(t *testing.T) {
	const robots = "User-agent: *\nCrawl-delay: 10\n"
	size := int64(Parse([]byte(robots), agent).Size())
	c, p, _ := newPaced(t, map[string]string{
		"example.com": robots, "b.example": robots, "c.example": robots,
	}, 2*size)
	ctx := context.Background()

	c.Check(ctx, example, "/a")
	p.Pace(example)
	for _, h := range []string{"b.example", "c.example"} {
		c.Check(ctx, Origin{Scheme: "https", Authority: h}, "/a")
	}
	if n, _ := c.Stats(); n != 2 {
		t.Fatalf("cache holds %d origins, want 2 after evicting example.com", n)
	}
	c.Check(ctx, example, "/a")
	if w := p.Pace(example); w != 10*time.Second {
		t.Fatalf("Pace after eviction = %v, want 10s", w)
	}
}

// Origins whose last request is longer ago than the cap are forgotten, so
// the Pacer holds only the origins it may still refuse.
func TestPaceForgets(t *testing.T) {
	c, p, clk := newPaced(
		t,
		map[string]string{"example.com": "User-agent: *\nCrawl-delay: 10\n"},
		1<<20,
	)
	c.Check(context.Background(), example, "/a")
	p.Pace(example)
	clk.advance(time.Minute)
	p.Pace(Origin{Scheme: "https", Authority: "other.example"})
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.last[example.key()]; ok || len(p.last) != 1 {
		t.Fatalf("Pacer holds %v", p.last)
	}
}
