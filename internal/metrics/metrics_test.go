package metrics

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/matchory/crawl-signer/internal/robots"
)

type fakeFetcher []struct {
	r   robots.Result
	err error
}

func (f *fakeFetcher) Fetch(context.Context, robots.Origin) (robots.Result, error) {
	x := (*f)[0]
	*f = (*f)[1:]
	return x.r, x.err
}

type fakeBackend struct{ err error }

func (b fakeBackend) Sign(context.Context, []byte) ([]byte, error) { return []byte("sig"), b.err }

func TestMetrics(t *testing.T) {
	reg := prometheus.NewPedanticRegistry()
	m := New(reg)

	f := m.Fetcher(&fakeFetcher{
		{r: robots.Result{Status: 200, Body: []byte("User-agent: *\nDisallow: /x\n")}},
		{r: robots.Result{Status: 503}},
		{err: errors.New("dial")},
	})
	now := time.Now()
	c := robots.NewCache(f, 1<<20, func() time.Time { return now })
	m.Cache(c)
	ctx := context.Background()
	c.Check(ctx, robots.Origin{Scheme: "https", Authority: "a.example"}, "/")
	c.Check(ctx, robots.Origin{Scheme: "https", Authority: "a.example"}, "/")
	c.Check(ctx, robots.Origin{Scheme: "https", Authority: "b.example"}, "/")
	c.Check(ctx, robots.Origin{Scheme: "https", Authority: "c.example"}, "/")

	m.Backend(fakeBackend{}).Sign(ctx, nil)
	m.Backend(fakeBackend{err: errors.New("down")}).Sign(ctx, nil)
	m.Verdict("ok")
	m.Verdict("robots")
	m.Verdict("ok")

	_, size := c.Stats()
	want := `
# HELP crawl_signer_requests_total Requests by verdict.
# TYPE crawl_signer_requests_total counter
crawl_signer_requests_total{verdict="ok"} 2
crawl_signer_requests_total{verdict="robots"} 1
# HELP crawl_signer_robots_cache_bytes Size of the cached robots.txt rules.
# TYPE crawl_signer_robots_cache_bytes gauge
crawl_signer_robots_cache_bytes ` + strconv.FormatInt(size, 10) + `
# HELP crawl_signer_robots_cache_entries Origins in the robots.txt cache.
# TYPE crawl_signer_robots_cache_entries gauge
crawl_signer_robots_cache_entries 3
# HELP crawl_signer_robots_cache_hits_total robots.txt checks answered from a fresh cache entry.
# TYPE crawl_signer_robots_cache_hits_total counter
crawl_signer_robots_cache_hits_total 1
# HELP crawl_signer_robots_cache_misses_total robots.txt checks that needed a fetch.
# TYPE crawl_signer_robots_cache_misses_total counter
crawl_signer_robots_cache_misses_total 3
# HELP crawl_signer_robots_fetch_total robots.txt fetches by outcome.
# TYPE crawl_signer_robots_fetch_total counter
crawl_signer_robots_fetch_total{outcome="2xx"} 1
crawl_signer_robots_fetch_total{outcome="5xx"} 1
crawl_signer_robots_fetch_total{outcome="error"} 1
# HELP crawl_signer_transit_sign_total OpenBao Transit sign calls by result.
# TYPE crawl_signer_transit_sign_total counter
crawl_signer_transit_sign_total{result="error"} 1
crawl_signer_transit_sign_total{result="ok"} 1
`
	names := []string{
		"crawl_signer_requests_total", "crawl_signer_robots_cache_bytes", "crawl_signer_robots_cache_entries",
		"crawl_signer_robots_cache_hits_total", "crawl_signer_robots_cache_misses_total",
		"crawl_signer_robots_fetch_total", "crawl_signer_transit_sign_total",
	}
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want), names...); err != nil {
		t.Error(err)
	}
	if n := testutil.CollectAndCount(m.signSeconds, "crawl_signer_transit_sign_seconds"); n != 1 {
		t.Errorf("sign histogram: %d series", n)
	}
}
