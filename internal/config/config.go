// Package config loads the signer's JSON configuration.
package config

import (
	"encoding/json"
	"fmt"
	"os"
)

type Config struct {
	Listen           string `json:"listen"`
	BaoSocket        string `json:"bao_socket"`
	EnvoySocket      string `json:"envoy_socket"`
	MetricsListen    string `json:"metrics_listen"`
	TransitKey       string `json:"transit_key"`
	KeyVersion       int    `json:"key_version"`
	KeyID            string `json:"keyid"`
	SignatureAgent   string `json:"signature_agent"`
	UserAgent        string `json:"user_agent"`
	From             string `json:"from"`
	RobotsCacheBytes int64  `json:"robots_cache_bytes"`
}

func Load(path string) (Config, error) {
	var c Config
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("parse %s: %w", path, err)
	}
	return c, c.validate()
}

func (c Config) validate() error {
	for name, v := range map[string]string{
		"listen": c.Listen, "bao_socket": c.BaoSocket, "envoy_socket": c.EnvoySocket,
		"transit_key": c.TransitKey, "keyid": c.KeyID, "signature_agent": c.SignatureAgent,
		"user_agent": c.UserAgent,
	} {
		if v == "" {
			return fmt.Errorf("config: %s is required", name)
		}
	}
	// Both values are embedded in quoted structured-field strings.
	for name, v := range map[string]string{"keyid": c.KeyID, "signature_agent": c.SignatureAgent} {
		for _, r := range v {
			if r < 0x20 || r > 0x7e || r == '"' || r == '\\' {
				return fmt.Errorf("config: %s contains a character not allowed in a structured-field string", name)
			}
		}
	}
	if c.KeyVersion < 1 {
		return fmt.Errorf("config: key_version must be >= 1")
	}
	if c.RobotsCacheBytes <= 0 {
		return fmt.Errorf("config: robots_cache_bytes must be > 0")
	}
	return nil
}
