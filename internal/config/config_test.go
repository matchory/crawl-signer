package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const valid = `{"listen":"127.0.0.1:9000","bao_socket":"/run/bao.sock","envoy_socket":"/run/envoy.sock",
"metrics_listen":"127.0.0.1:9100","transit_key":"crawl","key_version":2,"keyid":"kid",
"signature_agent":"sig.example","user_agent":"ua","from":"a@example.com","robots_cache_bytes":1048576}`

func write(t *testing.T, body string) string {
	p := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadValid(t *testing.T) {
	c, err := Load(write(t, valid))
	if err != nil {
		t.Fatal(err)
	}
	want := Config{"127.0.0.1:9000", "/run/bao.sock", "/run/envoy.sock", "127.0.0.1:9100", "crawl", 2,
		"kid", "sig.example", "ua", "a@example.com", 1048576}
	if c != want {
		t.Errorf("got %+v, want %+v", c, want)
	}
}

func TestLoadErrors(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("missing file: want error")
	}
	if _, err := Load(write(t, "{")); err == nil {
		t.Error("malformed JSON: want error")
	}
}

func TestLoadRejectsMissingFields(t *testing.T) {
	for _, tc := range []struct{ name, old, new string }{
		{"listen", `"listen":"127.0.0.1:9000"`, `"listen":""`},
		{"bao_socket", `"bao_socket":"/run/bao.sock"`, `"bao_socket":""`},
		{"envoy_socket", `"envoy_socket":"/run/envoy.sock"`, `"envoy_socket":""`},
		{"transit_key", `"transit_key":"crawl"`, `"transit_key":""`},
		{"keyid", `"keyid":"kid"`, `"keyid":""`},
		{"signature_agent", `"signature_agent":"sig.example"`, `"signature_agent":""`},
		{"user_agent", `"user_agent":"ua"`, `"user_agent":""`},
		{"key_version", `"key_version":2`, `"key_version":0`},
		{"robots_cache_bytes", `"robots_cache_bytes":1048576`, `"robots_cache_bytes":0`},
	} {
		if _, err := Load(write(t, strings.Replace(valid, tc.old, tc.new, 1))); err == nil {
			t.Errorf("%s: want error", tc.name)
		}
	}
}
