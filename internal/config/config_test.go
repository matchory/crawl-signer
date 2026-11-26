package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const valid = `{"listen":"/run/crawl-signer/grpc.sock","envoy_socket":"/run/envoy/internal.sock",
"metrics_listen":"127.0.0.1:9100","user_agent":"Mozilla/5.0 (compatible; ExampleBot/1.0)",
"from":"bot@example.com","signature_agent":"https://bot.example.com","robots_agent":"ExampleBot",
"robots_cache_bytes":1048576,"tailscale_whois":true,
"signing_key":{"keyid":"kid","transit":{"address":"unix:///run/bao.sock","key":"web-bot-auth","version":2}}}`

func write(t *testing.T, body string) string {
	t.Helper()
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
	tr := c.SigningKey.Transit
	if c.SignatureAgentForm != FormString {
		t.Errorf("signature_agent_form defaults to %q", c.SignatureAgentForm)
	}
	if c.DirectoryListen != "" {
		t.Errorf("directory_listen defaults to %q", c.DirectoryListen)
	}
	if c.MaxCrawlDelaySeconds != DefaultMaxCrawlDelaySeconds {
		t.Errorf("max_crawl_delay_seconds defaults to %d", c.MaxCrawlDelaySeconds)
	}
	if c.Listen != "/run/crawl-signer/grpc.sock" || c.RobotsAgent != "ExampleBot" ||
		!c.TailscaleWhois ||
		c.SigningKey.KeyID != "kid" ||
		tr == nil ||
		tr.Mount != DefaultTransitMount ||
		tr.Version != 2 ||
		tr.Key != "web-bot-auth" ||
		tr.Token != nil ||
		c.SigningKey.PrivateKey != nil {
		t.Errorf("got %+v, transit %+v", c, tr)
	}
}

func TestLoadPrivateKey(t *testing.T) {
	body := strings.Replace(
		valid,
		`"keyid":"kid","transit":{"address":"unix:///run/bao.sock","key":"web-bot-auth","version":2}`,
		`"private_key":{"filename":"/run/credentials/key.pem"}`,
		1,
	)
	c, err := Load(write(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if c.SigningKey.PrivateKey == nil ||
		c.SigningKey.PrivateKey.Filename != "/run/credentials/key.pem" ||
		c.SigningKey.Transit != nil ||
		c.SigningKey.KeyID != "" {
		t.Errorf("signing key %+v", c.SigningKey)
	}
}

func TestLoadErrors(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "missing.json")); err == nil {
		t.Error("missing file: want error")
	}
	if _, err := Load(write(t, "{")); err == nil {
		t.Error("malformed JSON: want error")
	}
	// A misspelt field would otherwise be ignored silently.
	if _, err := Load(write(t, strings.Replace(valid, `"from"`, `"form"`, 1))); err == nil {
		t.Error("unknown field: want error")
	}
}

func TestLoadRefuses(t *testing.T) {
	for _, tc := range []struct{ name, old, new string }{
		{"listen", `"listen":"/run/crawl-signer/grpc.sock"`, `"listen":""`},
		{"envoy_socket", `"envoy_socket":"/run/envoy/internal.sock"`, `"envoy_socket":""`},
		{"user_agent", `"user_agent":"Mozilla/5.0 (compatible; ExampleBot/1.0)"`, `"user_agent":""`},
		{"signature_agent", `"signature_agent":"https://bot.example.com"`, `"signature_agent":""`},
		{"robots_agent", `"robots_agent":"ExampleBot"`, `"robots_agent":""`},
		{"robots_agent not a token", `"robots_agent":"ExampleBot"`, `"robots_agent":"Example/Bot"`},
		{"robots_agent not in user_agent", `"robots_agent":"ExampleBot"`, `"robots_agent":"OtherBot"`},
		{"signature_agent not https", `"signature_agent":"https://bot.example.com"`, `"signature_agent":"http://bot.example.com"`},
		{"signature_agent without host", `"signature_agent":"https://bot.example.com"`, `"signature_agent":"https://"`},
		{"signature_agent with user", `"signature_agent":"https://bot.example.com"`, `"signature_agent":"https://u@bot.example.com"`},
		{"signature_agent_form", `"robots_agent"`, `"signature_agent_form":"list","robots_agent"`},
		{"robots_cache_bytes", `"robots_cache_bytes":1048576`, `"robots_cache_bytes":0`},
		{"max_crawl_delay_seconds", `"robots_cache_bytes"`, `"max_crawl_delay_seconds":-1,"robots_cache_bytes"`},
		{"no key", `"keyid":"kid","transit":{"address":"unix:///run/bao.sock","key":"web-bot-auth","version":2}`, `"keyid":"kid"`},
		{"both keys", `"version":2}`, `"version":2},"private_key":{"filename":"k"}`},
		{"transit keyid", `"keyid":"kid",`, ``},
		{"transit key", `"key":"web-bot-auth",`, ``},
		{"transit version", `"version":2`, `"version":0`},
		{"transit address", `"address":"unix:///run/bao.sock"`, `"address":"/run/bao.sock"`},
		{"transit address host", `"address":"unix:///run/bao.sock"`, `"address":"https://"`},
		{"transit token empty", `"version":2}`, `"version":2,"token":{}}`},
		{"transit token two", `"version":2}`, `"version":2,"token":{"filename":"t","inline_string":"x"}}`},
		{"private_key empty", `"keyid":"kid","transit":{"address":"unix:///run/bao.sock","key":"web-bot-auth","version":2}`, `"private_key":{}`},
	} {
		if _, err := Load(write(t, strings.Replace(valid, tc.old, tc.new, 1))); err == nil {
			t.Errorf("%s: want error", tc.name)
		}
	}
}

func TestLoadDirectoryListen(t *testing.T) {
	body := strings.Replace(
		valid,
		`"metrics_listen"`,
		`"directory_listen":"127.0.0.1:9200","metrics_listen"`,
		1,
	)
	c, err := Load(write(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if c.DirectoryListen != "127.0.0.1:9200" {
		t.Errorf("directory_listen = %q", c.DirectoryListen)
	}
}

func TestLoadMaxCrawlDelay(t *testing.T) {
	body := strings.Replace(
		valid,
		`"robots_cache_bytes"`,
		`"max_crawl_delay_seconds":5,"robots_cache_bytes"`,
		1,
	)
	c, err := Load(write(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if c.MaxCrawlDelaySeconds != 5 {
		t.Errorf("max_crawl_delay_seconds = %d, want 5", c.MaxCrawlDelaySeconds)
	}
}

func TestLoadAcceptsHTTPTransit(t *testing.T) {
	body := strings.Replace(
		valid,
		`"address":"unix:///run/bao.sock"`,
		`"address":"https://openbao.example.com:8200","mount":"bots","token":{"environment_variable":"BAO_TOKEN"}`,
		1,
	)
	c, err := Load(write(t, body))
	if err != nil {
		t.Fatal(err)
	}
	if tr := c.SigningKey.Transit; tr.Mount != "bots" ||
		tr.Token.EnvironmentVariable != "BAO_TOKEN" {
		t.Errorf("transit %+v", tr)
	}
}

func TestLoadRefusesUnsafeSFStrings(t *testing.T) {
	for _, bad := range []string{`a\"b`, `a\\\\b`, `a\nb`, `bü`} {
		for _, f := range []string{`"keyid":"kid"`, `"signature_agent":"https://bot.example.com"`} {
			name, _, _ := strings.Cut(f, ":")
			body := strings.Replace(valid, f, name+`:"`+bad+`"`, 1)
			if _, err := Load(write(t, body)); err == nil {
				t.Errorf("%s=%s: want error", name, bad)
			}
		}
	}
}

func TestDataSourceRead(t *testing.T) {
	p := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(p, []byte("from-file"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CRAWL_SIGNER_TEST_SECRET", "from-env")
	for _, tc := range []struct {
		d    DataSource
		want string
	}{
		{DataSource{Filename: p}, "from-file"},
		{DataSource{EnvironmentVariable: "CRAWL_SIGNER_TEST_SECRET"}, "from-env"},
		{DataSource{InlineString: "inline"}, "inline"},
	} {
		got, err := tc.d.Read()
		if err != nil || string(got) != tc.want {
			t.Errorf("%+v: got %q, %v", tc.d, got, err)
		}
	}
	if _, err := (DataSource{EnvironmentVariable: "CRAWL_SIGNER_TEST_UNSET"}).Read(); err == nil {
		t.Error("unset variable: want error")
	}
	if _, err := (DataSource{Filename: filepath.Join(t.TempDir(), "missing")}).Read(); err == nil {
		t.Error("missing file: want error")
	}
}
