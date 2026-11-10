// Package config loads the SIEPMU-SX YAML configuration.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Neurvinch/SIEPMU/server/internal/cryptoprov"
	"github.com/Neurvinch/SIEPMU/server/internal/events"
)

type GeoBox struct {
	Name   string  `yaml:"name"`
	MinLat float64 `yaml:"min_lat"`
	MaxLat float64 `yaml:"max_lat"`
	MinLon float64 `yaml:"min_lon"`
	MaxLon float64 `yaml:"max_lon"`
}

type Config struct {
	// Public origin the browser uses, e.g. https://siepmu.local:8443. Used for
	// WebAuthn RP ID/origin and DPoP htu checks.
	PublicOrigin string `yaml:"public_origin"`
	RPID         string `yaml:"rp_id"`
	RPName       string `yaml:"rp_name"`

	Listen string `yaml:"listen"` // public listener (Ring 1 gateway)
	// TLS: "internal-ca" (default) serves TLS 1.3 with an internal-CA certificate;
	// "upstream" serves plain HTTP behind a Ring 0 TLS terminator.
	TLS         string `yaml:"tls"`
	MeshListen  string `yaml:"mesh_listen"` // mTLS listener for mesh services
	DataDir     string `yaml:"data_dir"`
	WebDir      string `yaml:"web_dir"` // built web client to serve
	PostgresDSN string `yaml:"postgres_dsn"`
	RedisAddr   string `yaml:"redis_addr"`

	HSM    cryptoprov.PKCS11Config `yaml:"hsm"`
	Events events.Config           `yaml:"events"`

	// Optional CA bundle for smart-card (PIV/CAC) client certificates.
	SmartcardCAFile string `yaml:"smartcard_ca_file"`

	AccessTokenTTL   time.Duration `yaml:"access_token_ttl"`
	SessionTTL       time.Duration `yaml:"session_ttl"`
	SessionIdleTTL   time.Duration `yaml:"session_idle_ttl"`
	BreakglassTTL    time.Duration `yaml:"breakglass_ttl"`
	BreakglassQuorum int           `yaml:"breakglass_quorum"`

	Geofences []GeoBox `yaml:"geofences"`

	// Minimum browser major versions considered patched.
	MinBrowser map[string]int `yaml:"min_browser"`

	RateLimit struct {
		PerIPPerMinute   int `yaml:"per_ip_per_minute"`
		PerUserPerMinute int `yaml:"per_user_per_minute"`
		AuthPerIPPerMin  int `yaml:"auth_per_ip_per_minute"`
	} `yaml:"rate_limit"`

	Files struct {
		MaxSize   int64 `yaml:"max_size"`
		ChunkSize int   `yaml:"chunk_size"`
	} `yaml:"files"`

	Monitor struct {
		OpenSearchURL   string `yaml:"opensearch_url"`
		OpenSearchIndex string `yaml:"opensearch_index"`
		OpenSearchUser  string `yaml:"opensearch_user"`
		OpenSearchPass  string `yaml:"opensearch_pass"`
		WazuhLogFile    string `yaml:"wazuh_log_file"` // JSON lines for a Wazuh agent <localfile>
		WebhookURL      string `yaml:"webhook_url"`    // commander notification webhook
	} `yaml:"monitor"`

	Guard struct {
		// RED-side receiver public key (X-Wing), base64, and the diode target.
		ReceiverKEMPub string   `yaml:"receiver_kem_pub"`
		DiodeAddr      string   `yaml:"diode_addr"`
		Quorum         int      `yaml:"quorum"`
		DirtyWords     []string `yaml:"dirty_words"`
		MaxSize        int64    `yaml:"max_size"`
		AllowedTypes   []string `yaml:"allowed_types"`
	} `yaml:"guard"`
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &Config{}
	if err := yaml.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	c.defaults()
	if v := os.Getenv("SIEPMU_HSM_PIN"); v != "" {
		c.HSM.PIN = v
	}
	if v := os.Getenv("SIEPMU_POSTGRES_DSN"); v != "" {
		c.PostgresDSN = v
	}
	if c.PublicOrigin == "" || c.RPID == "" {
		return nil, fmt.Errorf("config: public_origin and rp_id are required")
	}
	return c, nil
}

func (c *Config) defaults() {
	if c.RPName == "" {
		c.RPName = "SIEPMU-SX"
	}
	if c.Listen == "" {
		c.Listen = ":8443"
	}
	if c.TLS == "" {
		c.TLS = "internal-ca"
	}
	if c.MeshListen == "" {
		c.MeshListen = ":9443"
	}
	if c.AccessTokenTTL == 0 {
		c.AccessTokenTTL = 5 * time.Minute
	}
	if c.SessionTTL == 0 {
		c.SessionTTL = 12 * time.Hour
	}
	if c.SessionIdleTTL == 0 {
		c.SessionIdleTTL = 30 * time.Minute
	}
	if c.BreakglassTTL == 0 {
		c.BreakglassTTL = time.Hour
	}
	if c.BreakglassQuorum == 0 {
		c.BreakglassQuorum = 2
	}
	if c.MinBrowser == nil {
		c.MinBrowser = map[string]int{"chrome": 128, "firefox": 128, "safari": 17, "edge": 128}
	}
	if c.RateLimit.PerIPPerMinute == 0 {
		c.RateLimit.PerIPPerMinute = 600
	}
	if c.RateLimit.PerUserPerMinute == 0 {
		c.RateLimit.PerUserPerMinute = 600
	}
	if c.RateLimit.AuthPerIPPerMin == 0 {
		c.RateLimit.AuthPerIPPerMin = 30
	}
	if c.Files.MaxSize == 0 {
		c.Files.MaxSize = 2 << 30
	}
	if c.Files.ChunkSize == 0 {
		c.Files.ChunkSize = 1 << 20
	}
	if c.Monitor.OpenSearchIndex == "" {
		c.Monitor.OpenSearchIndex = "siepmu-sec"
	}
	if c.Guard.Quorum == 0 {
		c.Guard.Quorum = 2
	}
	if c.Guard.MaxSize == 0 {
		c.Guard.MaxSize = 25 << 20
	}
	if len(c.Guard.AllowedTypes) == 0 {
		c.Guard.AllowedTypes = []string{"text/plain", "application/pdf", "image/png", "image/jpeg", "application/json"}
	}
	if c.Events.StoreDir == "" {
		c.Events.StoreDir = c.DataDir + "/jetstream"
	}
	if c.Events.Port == 0 {
		c.Events.Port = -1
	}
}
