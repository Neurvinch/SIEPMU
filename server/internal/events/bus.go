// Package events is the signed event fabric. It runs an embedded NATS
// server with JetStream (or connects to an external cluster) and exposes
// the subjects used between services:
//
//	siepmu.sec.<kind>      security telemetry, JetStream stream SEC (durable)
//	siepmu.deliver.<user>  realtime "new envelope" notifications (core NATS)
package events

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/Neurvinch/SIEPMU/server/internal/cryptoprov"
)

type Config struct {
	URL      string `yaml:"url"`       // external NATS; empty runs an embedded server
	StoreDir string `yaml:"store_dir"` // JetStream storage for the embedded server
	Port     int    `yaml:"port"`      // embedded server client port (-1 = in-process only)
}

type Bus struct {
	srv    *server.Server
	NC     *nats.Conn
	JS     jetstream.JetStream
	signer cryptoprov.Signer
	verify cryptoprov.Verifier
}

// SecEvent is the normalised security telemetry record (an OpenTelemetry-
// style log record with ATT&CK annotations).
type SecEvent struct {
	Time      time.Time      `json:"time"`
	Source    string         `json:"source"` // identity, gateway, policy, hsm, audit, suricata, zeek, falco, wazuh, bridge, guard
	Kind      string         `json:"kind"`
	Severity  int            `json:"severity"` // 0 info .. 4 critical
	UserID    string         `json:"user_id,omitempty"`
	IP        string         `json:"ip,omitempty"`
	AttackIDs []string       `json:"attack_ids,omitempty"`
	Summary   string         `json:"summary"`
	Data      map[string]any `json:"data,omitempty"`
}

// Signed wraps a payload with the publisher's composite signature so
// consumers can reject forged telemetry injected onto the bus.
type Signed struct {
	Payload   json.RawMessage `json:"payload"`
	Signature []byte          `json:"sig"`
	Key       []byte          `json:"key"`
}

func Start(ctx context.Context, cfg Config, signer cryptoprov.Signer, v cryptoprov.Verifier) (*Bus, error) {
	b := &Bus{signer: signer, verify: v}
	url := cfg.URL
	if url == "" {
		opts := &server.Options{
			ServerName: "siepmu-core",
			Host:       "127.0.0.1",
			Port:       cfg.Port,
			JetStream:  true,
			StoreDir:   cfg.StoreDir,
			NoSigs:     true,
		}
		if cfg.Port < 0 {
			opts.DontListen = true
		}
		srv, err := server.NewServer(opts)
		if err != nil {
			return nil, err
		}
		go srv.Start()
		if !srv.ReadyForConnections(10 * time.Second) {
			return nil, fmt.Errorf("events: embedded NATS not ready")
		}
		b.srv = srv
		nc, err := nats.Connect("", nats.InProcessServer(srv))
		if err != nil {
			return nil, err
		}
		b.NC = nc
	} else {
		nc, err := nats.Connect(url, nats.MaxReconnects(-1))
		if err != nil {
			return nil, err
		}
		b.NC = nc
	}
	js, err := jetstream.New(b.NC)
	if err != nil {
		return nil, err
	}
	b.JS = js
	if _, err := js.CreateOrUpdateStream(ctx, jetstream.StreamConfig{
		Name:      "SEC",
		Subjects:  []string{"siepmu.sec.>"},
		Storage:   jetstream.FileStorage,
		Retention: jetstream.LimitsPolicy,
		MaxAge:    30 * 24 * time.Hour,
	}); err != nil {
		return nil, fmt.Errorf("events: create SEC stream: %w", err)
	}
	return b, nil
}

func (b *Bus) sign(v any) ([]byte, error) {
	p, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	sig, err := b.signer.Sign(p)
	if err != nil {
		return nil, err
	}
	return json.Marshal(Signed{Payload: p, Signature: sig, Key: b.signer.PublicKey()})
}

// Open verifies a signed message against a set of trusted publisher keys.
func (b *Bus) Open(data []byte, trusted func(key []byte) bool, out any) error {
	var s Signed
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if !trusted(s.Key) {
		return fmt.Errorf("events: untrusted publisher key")
	}
	if err := b.verify.Verify(s.Key, s.Payload, s.Signature); err != nil {
		return err
	}
	return json.Unmarshal(s.Payload, out)
}

// PublishSec durably publishes a signed security event.
func (b *Bus) PublishSec(ctx context.Context, e SecEvent) error {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	data, err := b.sign(e)
	if err != nil {
		return err
	}
	_, err = b.JS.Publish(ctx, "siepmu.sec."+e.Kind, data)
	return err
}

// Notify sends a realtime notification to a user's connected clients.
func (b *Bus) Notify(userID string, v any) {
	data, err := json.Marshal(v)
	if err == nil {
		_ = b.NC.Publish("siepmu.deliver."+userID, data)
	}
}

func (b *Bus) PublicKey() []byte { return b.signer.PublicKey() }

func (b *Bus) Close() {
	if b.NC != nil {
		b.NC.Drain()
	}
	if b.srv != nil {
		b.srv.Shutdown()
		b.srv.WaitForShutdown()
	}
}
