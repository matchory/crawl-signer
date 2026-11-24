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
	return c, nil
}
