package robots

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/matchory/crawl-signer/internal/sign"
)

const (
	maxRedirects = 5
	// maxBody is RFC 9309's minimum parse limit; bytes past it are dropped.
	maxBody = 500 << 10
	// maxDrain is how much of a discarded body is read so the connection can be reused.
	maxDrain = 4 << 10
	// refusalHeader marks a response the gateway made itself, not the origin's.
	refusalHeader = "X-Crawl-Gateway-Refusal"
	schemeHTTP    = "http"
	schemeHTTPS   = "https"
)

// HTTPFetcher fetches robots.txt through Envoy's internal listener on Socket,
// so the fetch leaves through the same egress (and signing) as the crawl.
type HTTPFetcher struct {
	Socket string

	once   sync.Once
	client *http.Client
}

var envoyProxy = &url.URL{Scheme: schemeHTTP, Host: "envoy"}

// Fetch requests http://<authority>/robots.txt in absolute form; the gateway
// upgrades it to https unless X-Crawl-Scheme says http.
func (f *HTTPFetcher) Fetch(ctx context.Context, o Origin) (Result, error) {
	client := f.httpClient()
	target := &url.URL{Scheme: o.Scheme, Host: o.Authority, Path: "/robots.txt"}
	for hop := 0; ; hop++ {
		resp, err := f.get(ctx, client, target)
		if err != nil {
			return Result{}, err
		}
		if resp.Header.Get(refusalHeader) != "" {
			discard(resp)
			return Result{}, fmt.Errorf(
				"robots.txt for %s: gateway refused: %s",
				o.Authority,
				resp.Header.Get(refusalHeader),
			)
		}
		loc := resp.Header.Get("Location")
		if resp.StatusCode < 300 || resp.StatusCode >= 400 || loc == "" {
			return read(resp)
		}
		discard(resp)
		if hop == maxRedirects {
			return Result{}, fmt.Errorf(
				"robots.txt for %s: more than %d redirects",
				o.Authority,
				maxRedirects,
			)
		}
		next, err := target.Parse(loc)
		if err != nil || (next.Scheme != schemeHTTP && next.Scheme != schemeHTTPS) {
			return Result{}, fmt.Errorf("robots.txt for %s: bad redirect %q", o.Authority, loc)
		}
		auth := sign.CanonicalAuthority(next.Scheme, next.Host)
		if auth == "" {
			return Result{}, fmt.Errorf("robots.txt for %s: bad redirect %q", o.Authority, loc)
		}
		next.Host = auth
		target = next
	}
}

func (f *HTTPFetcher) httpClient() *http.Client {
	f.once.Do(func() {
		var d net.Dialer
		f.client = &http.Client{
			// Go writes absolute-form request targets only to a proxy, so
			// the socket poses as one.
			Transport: &http.Transport{
				Proxy: func(*http.Request) (*url.URL, error) { return envoyProxy, nil },
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return d.DialContext(ctx, "unix", f.Socket)
				},
				MaxIdleConns:    16,
				IdleConnTimeout: 90 * time.Second,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	})
	return f.client
}

func (f *HTTPFetcher) get(
	ctx context.Context,
	client *http.Client,
	target *url.URL,
) (*http.Response, error) {
	wire := *target
	wire.Scheme = schemeHTTP
	wire.Fragment = ""
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wire.String(), nil)
	if err != nil {
		return nil, err
	}
	if target.Scheme == schemeHTTP {
		req.Header.Set("X-Crawl-Scheme", "http")
	}
	return client.Do(req)
}

func read(resp *http.Response) (Result, error) {
	r := Result{Status: resp.StatusCode}
	r.MaxAge, r.HasMaxAge = maxAge(resp.Header.Values("Cache-Control"))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		discard(resp)
		return r, nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return Result{}, err
	}
	if len(body) > maxBody {
		// Drop the partial last line so a cut pattern cannot become a rule.
		body = body[:maxBody]
		body = body[:bytes.LastIndexAny(body, "\r\n")+1]
	}
	r.Body = body
	return r, nil
}

func discard(resp *http.Response) {
	_, _ = io.CopyN(io.Discard, resp.Body, maxDrain)
	_ = resp.Body.Close()
}

func maxAge(values []string) (time.Duration, bool) {
	for _, v := range values {
		for d := range strings.SplitSeq(v, ",") {
			name, val, ok := strings.Cut(strings.TrimSpace(d), "=")
			if !ok || !strings.EqualFold(name, "max-age") {
				continue
			}
			secs, err := strconv.ParseInt(strings.Trim(val, `"`), 10, 64)
			if err != nil || secs < 0 {
				continue
			}
			return time.Duration(min(secs, int64(maxTTL/time.Second))) * time.Second, true
		}
	}
	return 0, false
}
