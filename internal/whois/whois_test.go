package whois

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

type fakeSource struct {
	resp  *apitype.WhoIsResponse
	err   error
	calls []string
}

func (f *fakeSource) WhoIs(_ context.Context, addr string) (*apitype.WhoIsResponse, error) {
	f.calls = append(f.calls, addr)
	return f.resp, f.err
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

func TestLookupErrorNotCached(t *testing.T) {
	src := &fakeSource{err: errors.New("peer not found")}
	r := New(src, time.Now)
	for range 2 {
		if _, err := r.Lookup(context.Background(), addr); err == nil {
			t.Error("want error")
		}
	}
	if len(src.calls) != 2 {
		t.Errorf("error was cached: %d calls", len(src.calls))
	}

	src.err, src.resp = nil, &apitype.WhoIsResponse{}
	if _, err := r.Lookup(context.Background(), addr); err == nil {
		t.Error("a response without a node must be an error")
	}
}
