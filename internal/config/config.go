// Package config loads crawl-signer's JSON configuration.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
)

// Config is the whole configuration file. docs/reference/config.md describes
// every field.
type Config struct {
	Listen         string `json:"listen"`
	EnvoySocket    string `json:"envoy_socket"`
	MetricsListen  string `json:"metrics_listen"`
	UserAgent      string `json:"user_agent"`
	From           string `json:"from"`
	SignatureAgent string `json:"signature_agent"`
	// SignatureAgentForm is "string" (the default) or "dictionary".
	SignatureAgentForm string `json:"signature_agent_form"`
	RobotsAgent        string `json:"robots_agent"`
	RobotsCacheBytes   int64  `json:"robots_cache_bytes"`
	// MaxCrawlDelaySeconds caps the Crawl-delay crawl-signer applies.
	MaxCrawlDelaySeconds int        `json:"max_crawl_delay_seconds"`
	TailscaleWhois       bool       `json:"tailscale_whois"`
	SigningKey           SigningKey `json:"signing_key"`
}

// SigningKey says where the Ed25519 signing key is: exactly one of
// PrivateKey and Transit is set.
type SigningKey struct {
	// KeyID is the signature's keyid parameter. It is computed from a
	// private key when empty, and required with Transit, whose public key
	// crawl-signer does not read.
	KeyID      string      `json:"keyid"`
	PrivateKey *DataSource `json:"private_key"`
	Transit    *Transit    `json:"transit"`
}

// Transit is an OpenBao or Vault Transit key that signs on crawl-signer's
// behalf, so the private key never leaves the server.
type Transit struct {
	// Address is unix:///path for a local proxy's socket, or an http or
	// https URL.
	Address string `json:"address"`
	Mount   string `json:"mount"`
	Key     string `json:"key"`
	Version int    `json:"version"`
	// Token is the client token. Leave it out when a proxy in front of
	// the server adds the token itself.
	Token *DataSource `json:"token"`
}

// DataSource is a secret's location, in the shape of Envoy's
// config.core.v3.DataSource: exactly one field is set.
type DataSource struct {
	Filename            string `json:"filename"`
	EnvironmentVariable string `json:"environment_variable"`
	InlineString        string `json:"inline_string"`
}

// The forms of the Signature-Agent header.
const (
	FormString     = "string"
	FormDictionary = "dictionary"
)

// DefaultMaxCrawlDelaySeconds is the Crawl-delay cap when none is configured.
const DefaultMaxCrawlDelaySeconds = 60

// DefaultTransitMount is the mount Transit is read from when Mount is empty.
const DefaultTransitMount = "transit"

// Load reads and validates the configuration at path.
func Load(path string) (Config, error) {
	var c Config

	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}

	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()

	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("parse %s: %w", path, err)
	}

	if c.SignatureAgentForm == "" {
		c.SignatureAgentForm = FormString
	}

	if c.MaxCrawlDelaySeconds == 0 {
		c.MaxCrawlDelaySeconds = DefaultMaxCrawlDelaySeconds
	}

	if c.SigningKey.Transit != nil && c.SigningKey.Transit.Mount == "" {
		c.SigningKey.Transit.Mount = DefaultTransitMount
	}

	return c, c.validate()
}

// Read returns the secret's bytes.
func (d DataSource) Read() ([]byte, error) {
	switch {
	case d.Filename != "":
		return os.ReadFile(d.Filename)
	case d.EnvironmentVariable != "":
		v, ok := os.LookupEnv(d.EnvironmentVariable)
		if !ok || v == "" {
			return nil, fmt.Errorf("environment variable %s is not set", d.EnvironmentVariable)
		}

		return []byte(v), nil
	default:
		return []byte(d.InlineString), nil
	}
}

func (d DataSource) validate(name string) error {
	set := 0

	for _, v := range []string{d.Filename, d.EnvironmentVariable, d.InlineString} {
		if v != "" {
			set++
		}
	}

	if set != 1 {
		return fmt.Errorf(
			"config: %s needs exactly one of filename, environment_variable and inline_string",
			name,
		)
	}

	return nil
}

func (c Config) validate() error {
	for _, f := range []struct{ name, value string }{
		{"listen", c.Listen},
		{"envoy_socket", c.EnvoySocket},
		{"user_agent", c.UserAgent},
		{"signature_agent", c.SignatureAgent},
		{"robots_agent", c.RobotsAgent},
	} {
		if f.value == "" {
			return fmt.Errorf("config: %s is required", f.name)
		}
	}

	// Both values are embedded in quoted structured-field strings.
	for _, f := range []struct{ name, value string }{
		{"signing_key.keyid", c.SigningKey.KeyID},
		{"signature_agent", c.SignatureAgent},
	} {
		if !sfString(f.value) {
			return fmt.Errorf(
				"config: %s contains a character not allowed in a structured-field string",
				f.name,
			)
		}
	}

	if err := c.validateAgents(); err != nil {
		return err
	}

	if c.SignatureAgentForm != FormString && c.SignatureAgentForm != FormDictionary {
		return errors.New(`config: signature_agent_form must be "string" or "dictionary"`)
	}

	// Verifiers fetch the key directory from this URL.
	if !strings.HasPrefix(c.SignatureAgent, "https://") {
		return errors.New("config: signature_agent must be an https:// URL")
	}

	if c.RobotsCacheBytes <= 0 {
		return errors.New("config: robots_cache_bytes must be > 0")
	}

	if c.MaxCrawlDelaySeconds < 0 {
		return errors.New("config: max_crawl_delay_seconds must not be negative")
	}

	return c.SigningKey.validate()
}

// validateAgents ties the robots.txt product token to the User-Agent, as
// RFC 9309 section 2.2.1 asks: a site's rules for the crawler must name what
// the site sees in its logs.
func (c Config) validateAgents() error {
	for _, r := range c.RobotsAgent {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && r != '_' && r != '-' {
			return errors.New(
				"config: robots_agent may contain only letters, '_' and '-' (RFC 9309)",
			)
		}
	}

	if !strings.Contains(strings.ToLower(c.UserAgent), strings.ToLower(c.RobotsAgent)) {
		return errors.New("config: user_agent must contain robots_agent")
	}

	return nil
}

func (k SigningKey) validate() error {
	switch {
	case (k.PrivateKey == nil) == (k.Transit == nil):
		return errors.New("config: signing_key needs exactly one of private_key and transit")
	case k.PrivateKey != nil:
		return k.PrivateKey.validate("signing_key.private_key")
	}

	t := k.Transit
	if k.KeyID == "" {
		return errors.New("config: signing_key.keyid is required with transit")
	}

	if t.Key == "" {
		return errors.New("config: signing_key.transit.key is required")
	}

	if t.Version < 1 {
		return errors.New("config: signing_key.transit.version must be >= 1")
	}

	if !validAddress(t.Address) {
		return errors.New(
			"config: signing_key.transit.address must be unix:///path or an http(s) URL",
		)
	}

	if t.Token != nil {
		return t.Token.validate("signing_key.transit.token")
	}

	return nil
}

// sfString reports whether s fits an RFC 8941 sf-string without escapes.
func sfString(s string) bool {
	for _, r := range s {
		if r < 0x20 || r > 0x7e || r == '"' || r == '\\' {
			return false
		}
	}

	return true
}

// validAddress reports whether a is unix:///path or an http(s) URL with a host.
func validAddress(a string) bool {
	u, err := url.Parse(a)
	if err != nil {
		return false
	}

	switch u.Scheme {
	case "unix":
		return u.Path != ""
	case "http", "https":
		return u.Host != ""
	}

	return false
}
