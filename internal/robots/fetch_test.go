package robots

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// gateway stands in for Envoy's internal listener: it serves absolute-form
// requests on a unix socket and hands them to h.
func gateway(t *testing.T, h http.HandlerFunc) *HTTPFetcher {
	t.Helper()
	// t.TempDir() can exceed the unix socket path limit on macOS.
	dir, err := os.MkdirTemp("", "robots") //nolint:usetesting // see above
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock := filepath.Join(dir, "s")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return &HTTPFetcher{Socket: sock}
}

func TestFetchRequestShape(t *testing.T) {
	type seen struct{ uri, host, scheme string }
	got := make(chan seen, 2)
	f := gateway(t, func(w http.ResponseWriter, r *http.Request) {
		got <- seen{r.RequestURI, r.Host, r.Header.Get("X-Crawl-Scheme")}
		w.Header().Set("Cache-Control", "public, Max-Age=7200")
		fmt.Fprint(w, "User-agent: *\nDisallow: /x\n")
	})
	ctx := context.Background()

	res, err := f.Fetch(ctx, Origin{Scheme: "https", Authority: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if s := <-got; s != (seen{"http://example.com/robots.txt", "example.com", ""}) {
		t.Errorf("https origin: request %+v", s)
	}
	if res.Status != 200 || !res.HasMaxAge || res.MaxAge != 2*time.Hour ||
		!strings.Contains(string(res.Body), "Disallow: /x") {
		t.Errorf("result %+v", res)
	}

	if _, err := f.Fetch(ctx, Origin{Scheme: "http", Authority: "example.com:8080"}); err != nil {
		t.Fatal(err)
	}
	if s := <-got; s != (seen{"http://example.com:8080/robots.txt", "example.com:8080", "http"}) {
		t.Errorf("http origin: request %+v", s)
	}
}

func TestFetchEdgeCases(t *testing.T) {
	big := "User-agent: *\nDisallow: /early\n" + strings.Repeat(
		"#"+strings.Repeat("x", 1022)+"\n",
		2048,
	) + "Disallow: /late\n"
	f := gateway(t, func(w http.ResponseWriter, r *http.Request) {
		scheme := r.Header.Get("X-Crawl-Scheme")
		switch {
		case r.Host == "old.example" && scheme == "":
			http.Redirect(w, r, "http://new.example/robots.txt", http.StatusMovedPermanently)
		case r.Host == "new.example" && scheme == "http":
			http.Redirect(w, r, "https://final.example/robots.txt", http.StatusFound)
		case r.Host == "final.example" && scheme == "":
			fmt.Fprint(w, "User-agent: ExampleBot\nDisallow: /moved\n")
		case strings.HasPrefix(r.Host, "loop"):
			var n int
			fmt.Sscanf(r.Host, "loop%d.example", &n)
			if n >= 10 {
				http.NotFound(w, r)
				return
			}
			http.Redirect(
				w,
				r,
				fmt.Sprintf("https://loop%d.example/robots.txt", n+1),
				http.StatusFound,
			)
		case r.Host == "rel.example":
			if r.URL.Path == "/robots.txt" {
				http.Redirect(w, r, "/real/robots.txt", http.StatusFound)
				return
			}
			fmt.Fprint(w, "User-agent: *\nDisallow: /rel\n")
		case r.Host == "refused.example":
			w.Header().Set("X-Crawl-Gateway-Refusal", "destination not allowed")
			http.Error(w, "refused", http.StatusForbidden)
		case r.Host == "oneline.example":
			fmt.Fprint(w, "User-agent: * Disallow: /"+strings.Repeat("x", 2<<20))
		case r.Host == "big.example":
			fmt.Fprint(w, big)
		case r.Host == "html.example":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(
				w,
				"<!doctype html><html><head><title>Home</title></head><body>Welcome</body></html>",
			)
		default:
			http.NotFound(w, r)
		}
	})
	clk := newClock()
	c := NewCache(f, agent, 1<<20, clk.now)
	ctx := context.Background()
	o := func(h string) Origin { return Origin{Scheme: "https", Authority: h} }

	t.Run("redirect to another host", func(t *testing.T) {
		if got := c.Check(ctx, o("old.example"), "/moved/x"); got != Disallowed {
			t.Errorf("Check = %v, want Disallowed", got)
		}
		if got := c.Check(ctx, o("old.example"), "/other"); got != Allowed {
			t.Errorf("Check = %v, want Allowed", got)
		}
	})
	t.Run("relative redirect", func(t *testing.T) {
		if got := c.Check(ctx, o("rel.example"), "/rel"); got != Disallowed {
			t.Errorf("Check = %v, want Disallowed", got)
		}
	})
	t.Run("five redirects are followed", func(t *testing.T) {
		res, err := f.Fetch(ctx, o("loop5.example"))
		if err != nil || res.Status != 404 {
			t.Errorf("Fetch = %+v, %v; want the 404 at loop10", res, err)
		}
	})
	t.Run("six redirects are unreachable", func(t *testing.T) {
		if _, err := f.Fetch(ctx, o("loop4.example")); err == nil {
			t.Error("Fetch: want an error after 6 redirects")
		}
		if got := c.Check(ctx, o("loop4.example"), "/"); got != Unavailable {
			t.Errorf("Check = %v, want Unavailable", got)
		}
	})
	t.Run("body cut at 500 KiB", func(t *testing.T) {
		res, err := f.Fetch(ctx, o("big.example"))
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Body) > 500<<10 {
			t.Errorf("body %d bytes, want <= %d", len(res.Body), 500<<10)
		}
		if got := c.Check(ctx, o("big.example"), "/early"); got != Disallowed {
			t.Errorf("Check(/early) = %v, want Disallowed", got)
		}
		if got := c.Check(ctx, o("big.example"), "/late"); got != Allowed {
			t.Errorf("Check(/late) = %v, want Allowed", got)
		}
	})
	t.Run("gateway refusal is a failure, not a 4xx", func(t *testing.T) {
		if _, err := f.Fetch(ctx, o("refused.example")); err == nil {
			t.Error("Fetch: want an error")
		}
		if got := c.Check(ctx, o("refused.example"), "/"); got != Unavailable {
			t.Errorf("Check = %v, want Unavailable", got)
		}
	})
	t.Run("no newline before the cut parses nothing", func(t *testing.T) {
		res, err := f.Fetch(ctx, o("oneline.example"))
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Body) != 0 {
			t.Errorf("body %d bytes, want none", len(res.Body))
		}
		if got := c.Check(ctx, o("oneline.example"), "/"); got != Allowed {
			t.Errorf("Check = %v, want Allowed", got)
		}
	})
	t.Run("HTML 200 allows", func(t *testing.T) {
		if got := c.Check(ctx, o("html.example"), "/a"); got != Allowed {
			t.Errorf("Check = %v, want Allowed", got)
		}
	})
}

func TestFetchUnreachableSocket(t *testing.T) {
	f := &HTTPFetcher{Socket: filepath.Join(os.TempDir(), "robots-no-such-socket")}
	if _, err := f.Fetch(
		context.Background(),
		Origin{Scheme: "https", Authority: "example.com"},
	); err == nil {
		t.Fatal("Fetch: want an error")
	}
}
