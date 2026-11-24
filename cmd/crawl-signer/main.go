package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"tailscale.com/client/local"

	"github.com/matchory/crawl-signer/internal/config"
	"github.com/matchory/crawl-signer/internal/extproc"
	"github.com/matchory/crawl-signer/internal/metrics"
	"github.com/matchory/crawl-signer/internal/robots"
	"github.com/matchory/crawl-signer/internal/sign"
	"github.com/matchory/crawl-signer/internal/whois"
)

var version = "dev"

func main() {
	path := flag.String("config", "", "path to the JSON config file")
	flag.Parse()
	if err := run(*path); err != nil {
		fmt.Fprintln(os.Stderr, "crawl-signer:", err)
		os.Exit(1)
	}
}

func run(path string) error {
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}

	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	m := metrics.New(reg)

	signer := sign.NewSigner(m.Backend(sign.NewTransit(cfg.BaoSocket, cfg.TransitKey, cfg.KeyVersion)), cfg, time.Now)
	cache := robots.NewCache(m.Fetcher(&robots.HTTPFetcher{Socket: cfg.EnvoySocket}), cfg.RobotsCacheBytes, time.Now)
	m.Cache(cache)
	srv := extproc.New(cfg, cache, signer, whois.New(&local.Client{}, time.Now))
	srv.Count = m.Verdict

	if err := os.Remove(cfg.Listen); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	lis, err := net.Listen("unix", cfg.Listen)
	if err != nil {
		return err
	}
	if err := os.Chmod(cfg.Listen, 0o660); err != nil {
		return err
	}

	g := grpc.NewServer()
	extprocv3.RegisterExternalProcessorServer(g, srv)
	errc := make(chan error, 2)
	go func() { errc <- g.Serve(lis) }()

	var metricsSrv *http.Server
	if cfg.MetricsListen != "" {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
		metricsSrv = &http.Server{Addr: cfg.MetricsListen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
		go func() { errc <- fmt.Errorf("metrics: %w", metricsSrv.ListenAndServe()) }()
	}
	log.Printf("crawl-signer %s listening on %s", version, cfg.Listen)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	select {
	case err := <-errc:
		g.Stop()
		return err
	case <-sig:
	}
	if metricsSrv != nil {
		metricsSrv.Close()
	}
	// Each ext_proc stream is one HTTP request, so draining is quick; the
	// timer only cuts off a stuck stream.
	t := time.AfterFunc(10*time.Second, g.Stop)
	defer t.Stop()
	g.GracefulStop()
	return nil
}
