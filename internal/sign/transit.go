package sign

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	transitTimeout = 2 * time.Second
	maxResponse    = 64 << 10
)

// Transit signs with an OpenBao or Vault Transit key. The private key stays
// in the server; crawl-signer only sends what it needs signed.
type Transit struct {
	endpoint string
	version  int
	token    string
	hc       *http.Client
}

// NewTransit returns a Transit client. address is unix:///path or an http(s)
// URL; token may be empty when a proxy in front of the server adds it.
func NewTransit(address, mount, key string, version int, token string) (*Transit, error) {
	u, err := url.Parse(address)
	if err != nil {
		return nil, fmt.Errorf("transit address: %w", err)
	}

	t := &Transit{version: version, token: token, hc: &http.Client{}}
	base := strings.TrimSuffix(u.String(), "/")

	if u.Scheme == "unix" {
		socket := u.Path
		t.hc.Transport = &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socket)
			},
		}
		base = "http://transit"
	}

	t.endpoint = base + "/v1/" + strings.Trim(mount, "/") + "/sign/" + url.PathEscape(key)

	return t, nil
}

// Sign implements Backend.
func (t *Transit) Sign(ctx context.Context, msg []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, transitTimeout)
	defer cancel()

	body, err := json.Marshal(map[string]any{
		"input":       base64.StdEncoding.EncodeToString(msg),
		"key_version": t.version,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	if t.token != "" {
		req.Header.Set("X-Vault-Token", t.token)
	}

	resp, err := t.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("transit sign: %w", err)
	}
	defer resp.Body.Close()

	// The body is not part of the error: a server can echo the request.
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("transit sign: status %d", resp.StatusCode)
	}

	var out struct {
		Data struct {
			Signature string `json:"signature"`
		} `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponse)).Decode(&out); err != nil {
		return nil, fmt.Errorf("transit sign: decode: %w", err)
	}

	// "vault:v<N>:<base64>"
	parts := strings.SplitN(out.Data.Signature, ":", 3)
	if len(parts) != 3 {
		return nil, errors.New("transit sign: malformed signature")
	}

	return base64.StdEncoding.DecodeString(parts[2])
}
