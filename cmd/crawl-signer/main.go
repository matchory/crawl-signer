// Command crawl-signer is Envoy's external processor for a crawl gateway: it
// enforces request rules and robots.txt, and signs what it lets through with
// Web Bot Auth. See https://github.com/matchory/crawl-signer.
package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	extprocv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"tailscale.com/client/local"

	"github.com/matchory/crawl-signer/internal/config"
	"github.com/matchory/crawl-signer/internal/directory"
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
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	m := metrics.New(reg)

	backend, pub, keyid, err := signingBackend(context.Background(), cfg.SigningKey)
	if err != nil {
		return err
	}
	cfg.SigningKey.KeyID = keyid

	agent := sign.Agent{
		URL:        cfg.SignatureAgent,
		Dictionary: cfg.SignatureAgentForm == config.FormDictionary,
	}
	signer := sign.NewSigner(m.Backend(backend), agent, keyid, time.Now)
	cache := robots.NewCache(
		m.Fetcher(&robots.HTTPFetcher{Socket: cfg.EnvoySocket}),
		cfg.RobotsAgent,
		cfg.RobotsCacheBytes,
		time.Now,
	)
	pacer := robots.NewPacer(
		cache.Delay,
		time.Duration(cfg.MaxCrawlDelaySeconds)*time.Second,
		time.Now,
	)
	m.Cache(cache)

	var who extproc.Whois
	if cfg.TailscaleWhois {
		who = whois.New(&local.Client{}, time.Now)
	}

	srv := extproc.New(cfg, cache, pacer, signer, who)
	srv.Count = m.Verdict

	if err := os.Remove(cfg.Listen); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	lis, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", cfg.Listen)
	if err != nil {
		return err
	}
	// Envoy connects as another user that shares the socket's group.
	//nolint:gosec // G302: a socket needs write permission to be connected to.
	if err := os.Chmod(cfg.Listen, 0o660); err != nil {
		return err
	}

	g := grpc.NewServer()
	extprocv3.RegisterExternalProcessorServer(g, srv)
	errc := make(chan error, 3)
	go func() { errc <- g.Serve(lis) }()

	var dirSrv *http.Server
	if cfg.DirectoryListen != "" {
		d, err := directory.New(m.Backend(backend), pub, cfg.SignatureAgent, time.Now)
		if err != nil {
			g.Stop()
			return err
		}
		dirSrv = &http.Server{
			Addr:              cfg.DirectoryListen,
			Handler:           d,
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() { errc <- fmt.Errorf("directory: %w", dirSrv.ListenAndServe()) }()
	}

	var metricsSrv *http.Server
	if cfg.MetricsListen != "" {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
		metricsSrv = &http.Server{
			Addr:              cfg.MetricsListen,
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() { errc <- fmt.Errorf("metrics: %w", metricsSrv.ListenAndServe()) }()
	}
	log.Printf("crawl-signer %s listening on %s, signing with keyid %s", version, cfg.Listen, keyid)

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
	if dirSrv != nil {
		dirSrv.Close()
	}
	// Each ext_proc stream is one HTTP request, so draining is quick; the
	// timer only cuts off a stuck stream.
	t := time.AfterFunc(10*time.Second, g.Stop)
	defer t.Stop()
	g.GracefulStop()
	return nil
}

// signingBackend opens the configured key and returns it with its public
// key and keyid. The keyid must be the public key's thumbprint, so the
// published key directory and the signatures cannot disagree: it is computed
// for a private key when not configured, and a Transit key's public key is
// read from Transit to check it.
func signingBackend(
	ctx context.Context,
	k config.SigningKey,
) (sign.Backend, ed25519.PublicKey, string, error) {
	if t := k.Transit; t != nil {
		var token string

		if t.Token != nil {
			b, err := t.Token.Read()
			if err != nil {
				return nil, nil, "", fmt.Errorf("signing_key.transit.token: %w", err)
			}

			token = strings.TrimSpace(string(b))
		}

		tr, err := sign.NewTransit(t.Address, t.Mount, t.Key, t.Version, token)
		if err != nil {
			return nil, nil, "", err
		}

		pub, err := tr.PublicKey(ctx)
		if err != nil {
			return nil, nil, "", fmt.Errorf("signing_key.transit: %w", err)
		}

		if keyid := sign.Thumbprint(pub); keyid != k.KeyID {
			return nil, nil, "", fmt.Errorf(
				"signing_key.keyid is %s, but the Transit key's thumbprint is %s",
				k.KeyID,
				keyid,
			)
		}

		return tr, pub, k.KeyID, nil
	}

	b, err := k.PrivateKey.Read()
	if err != nil {
		return nil, nil, "", fmt.Errorf("signing_key.private_key: %w", err)
	}

	key, err := sign.NewLocalKey(b)
	if err != nil {
		return nil, nil, "", err
	}

	keyid := sign.Thumbprint(key.Public())
	if k.KeyID != "" && k.KeyID != keyid {
		return nil, nil, "", fmt.Errorf(
			"signing_key.keyid is %s, but the private key's thumbprint is %s",
			k.KeyID,
			keyid,
		)
	}

	return key, key.Public(), keyid, nil
}
