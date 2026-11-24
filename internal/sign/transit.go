package sign

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
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

// Transit signs through the OpenBao Proxy's unix socket, which injects the
// token; no credential is handled here.
type Transit struct {
	Socket  string
	Key     string
	Version int

	client *http.Client
}

func NewTransit(socket, key string, version int) *Transit {
	return &Transit{Socket: socket, Key: key, Version: version, client: &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
	}}}
}

func (t *Transit) Sign(ctx context.Context, msg []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, transitTimeout)
	defer cancel()

	body, err := json.Marshal(map[string]any{
		"input":       base64.StdEncoding.EncodeToString(msg),
		"key_version": t.Version,
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://bao/v1/transit/sign/"+url.PathEscape(t.Key), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("transit sign: %w", err)
	}
	defer resp.Body.Close()
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
		return nil, fmt.Errorf("transit sign: malformed signature")
	}
	return base64.StdEncoding.DecodeString(parts[2])
}
