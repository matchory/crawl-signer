package whois

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

type fakeSource struct {
	resp  *apitype.WhoIsResponse
	err   error
	gate  chan struct{} // if set, WhoIs waits for it or for ctx
	mu    sync.Mutex
	calls []string
}

func (f *fakeSource) WhoIs(ctx context.Context, addr string) (*apitype.WhoIsResponse, error) {
	f.mu.Lock()
	f.calls = append(f.calls, addr)
	f.mu.Unlock()
	if f.gate != nil {
		select {
		case <-f.gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return f.resp, f.err
}

func (f *fakeSource) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

var addr = netip.MustParseAddr("100.101.102.103")

func TestLookupCaches(t *testing.T) {
	src := &fakeSource{resp: &apitype.WhoIsResponse{Node: &tailcfg.Node{
		Name: "whale-1.tail1234.ts.net.", Tags: []string{"tag:crawler", "tag:pipeline"},
	}}}
	now := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)
	r := New(src, func() time.Time { return now })

	c, err := r.Lookup(context.Background(), addr)
	if err != nil {
		t.Fatal(err)
	}
	if c.Node != "whale-1" || !slices.Equal(c.Tags, []string{"tag:crawler", "tag:pipeline"}) {
		t.Errorf("got %+v", c)
	}
	if !slices.Equal(src.calls, []string{"100.101.102.103"}) {
		t.Errorf("calls: %v", src.calls)
	}

	now = now.Add(10*time.Minute - time.Second)
	r.Lookup(context.Background(), addr)
	if len(src.calls) != 1 {
		t.Errorf("cached lookup went to LocalAPI: %d calls", len(src.calls))
	}
	now = now.Add(time.Second)
	r.Lookup(context.Background(), addr)
	if len(src.calls) != 2 {
		t.Errorf("expired lookup not refreshed: %d calls", len(src.calls))
	}
}

func TestLookupNoNode(t *testing.T) {
	src := &fakeSource{resp: &apitype.WhoIsResponse{}}
	if _, err := New(src, time.Now).Lookup(context.Background(), addr); err == nil {
		t.Error("a response without a node must be an error")
	}
}

func TestLookupNegativeCache(t *testing.T) {
	src := &fakeSource{err: errors.New("tailscaled down")}
	now := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)
	r := New(src, func() time.Time { return now })
	r.Lookup(context.Background(), addr)
	now = now.Add(5*time.Second - time.Millisecond)
	if _, err := r.Lookup(context.Background(), addr); err == nil || len(src.calls) != 1 {
		t.Errorf("failure not cached: err %v, %d calls", err, len(src.calls))
	}
	now = now.Add(time.Millisecond)
	src.err, src.resp = nil, &apitype.WhoIsResponse{Node: &tailcfg.Node{Name: "whale-1.ts.net."}}
	if c, err := r.Lookup(context.Background(), addr); err != nil || c.Node != "whale-1" || len(src.calls) != 2 {
		t.Errorf("after 5 s: %+v, %v, %d calls", c, err, len(src.calls))
	}
}

func TestLookupEmptyName(t *testing.T) {
	src := &fakeSource{resp: &apitype.WhoIsResponse{Node: &tailcfg.Node{Tags: []string{"tag:x"}}}}
	c, err := New(src, time.Now).Lookup(context.Background(), addr)
	if err != nil || c.Node != "unknown" {
		t.Errorf("got %+v, %v", c, err)
	}
}

func TestCallerCancelNotCached(t *testing.T) {
	src := &fakeSource{gate: make(chan struct{}), resp: &apitype.WhoIsResponse{Node: &tailcfg.Node{Name: "whale-1.ts.net."}}}
	r := New(src, time.Now)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.Lookup(ctx, addr); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}
	close(src.gate)
	c, err := r.Lookup(context.Background(), addr)
	if err != nil || c.Node != "whale-1" {
		t.Errorf("caller's cancellation was cached: %+v, %v", c, err)
	}
}

func TestLookupTimeoutCached(t *testing.T) {
	old := timeout
	timeout = 10 * time.Millisecond
	defer func() { timeout = old }()
	src := &fakeSource{gate: make(chan struct{})}
	r := New(src, time.Now)
	if _, err := r.Lookup(context.Background(), addr); err == nil {
		t.Fatal("want timeout error")
	}
	if _, err := r.Lookup(context.Background(), addr); err == nil || src.count() != 1 {
		t.Errorf("a hung tailscaled was not negative-cached: %v, %d calls", err, src.count())
	}
}

func TestConcurrentLookupsShareOneQuery(t *testing.T) {
	src := &fakeSource{gate: make(chan struct{}), resp: &apitype.WhoIsResponse{Node: &tailcfg.Node{Name: "whale-1.ts.net."}}}
	r := New(src, time.Now)
	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.Lookup(context.Background(), addr)
		}()
	}
	for src.count() == 0 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	close(src.gate)
	wg.Wait()
	if n := src.count(); n != 1 {
		t.Errorf("%d LocalAPI calls, want 1", n)
	}
}
