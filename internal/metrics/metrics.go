// Package metrics exposes crawl-signer's Prometheus metrics. It wraps the
// robots and sign components instead of reaching into them.
package metrics

import (
	"context"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/matchory/crawl-signer/internal/robots"
	"github.com/matchory/crawl-signer/internal/sign"
)

// Metrics holds crawl-signer's metrics.
type Metrics struct {
	reg         prometheus.Registerer
	requests    *prometheus.CounterVec
	hits        prometheus.Counter
	misses      prometheus.Counter
	fetches     *prometheus.CounterVec
	signs       *prometheus.CounterVec
	signSeconds prometheus.Histogram
}

// New registers crawl-signer's metrics with reg.
func New(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		reg: reg,
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "crawl_signer_requests_total", Help: "Requests by verdict.",
		}, []string{"verdict"}),
		hits: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "crawl_signer_robots_cache_hits_total",
			Help: "robots.txt checks answered from a fresh cache entry.",
		}),
		misses: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "crawl_signer_robots_cache_misses_total",
			Help: "robots.txt checks that needed a fetch.",
		}),
		fetches: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "crawl_signer_robots_fetch_total", Help: "robots.txt fetches by outcome.",
		}, []string{"outcome"}),
		signs: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "crawl_signer_sign_total", Help: "Signing key calls by result.",
		}, []string{"result"}),
		signSeconds: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "crawl_signer_sign_seconds", Help: "Signing key call duration.",
		}),
	}
	reg.MustRegister(m.requests, m.hits, m.misses, m.fetches, m.signs, m.signSeconds)
	// Present from the start, so an alert's rate() sees the first error.
	m.signs.WithLabelValues("ok")
	m.signs.WithLabelValues("error")
	return m
}

// Verdict counts one request; it fits extproc.Server.Count.
func (m *Metrics) Verdict(v string) { m.requests.WithLabelValues(v).Inc() }

// Cache registers c's size gauges and counts its hits and misses.
func (m *Metrics) Cache(c *robots.Cache) {
	c.OnLookup = func(hit bool) {
		if hit {
			m.hits.Inc()
		} else {
			m.misses.Inc()
		}
	}
	m.reg.MustRegister(
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "crawl_signer_robots_cache_entries", Help: "Origins in the robots.txt cache.",
		}, func() float64 { n, _ := c.Stats(); return float64(n) }),
		prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "crawl_signer_robots_cache_bytes", Help: "Size of the cached robots.txt rules.",
		}, func() float64 { _, b := c.Stats(); return float64(b) }),
	)
}

type fetcher struct {
	m *Metrics
	f robots.Fetcher
}

// Fetcher wraps f to count robots.txt fetches by outcome.
func (m *Metrics) Fetcher(f robots.Fetcher) robots.Fetcher { return fetcher{m, f} }

func (w fetcher) Fetch(ctx context.Context, o robots.Origin) (robots.Result, error) {
	r, err := w.f.Fetch(ctx, o)
	outcome := "error"
	if err == nil {
		outcome = strconv.Itoa(r.Status/100) + "xx"
	}
	w.m.fetches.WithLabelValues(outcome).Inc()
	return r, err
}

type backend struct {
	m *Metrics
	b sign.Backend
}

// Backend wraps b to count and time signing calls.
func (m *Metrics) Backend(b sign.Backend) sign.Backend { return backend{m, b} }

func (w backend) Sign(ctx context.Context, msg []byte) ([]byte, error) {
	start := time.Now()
	sig, err := w.b.Sign(ctx, msg)
	w.m.signSeconds.Observe(time.Since(start).Seconds())
	result := "ok"
	if err != nil {
		result = "error"
	}
	w.m.signs.WithLabelValues(result).Inc()
	return sig, err
}
