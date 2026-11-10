// Package bridge is the legacy integration bridge: protocol adapters turn
// legacy traffic into signed JSON envelopes at the bridge boundary, a
// durable spool provides store-and-forward across link or mesh outages, and
// an idempotent grow-only-set sync delivers every envelope exactly once.
package bridge

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"

	"github.com/Neurvinch/SIEPMU/server/internal/cryptoprov"
)

// Envelope is the normalised form of one legacy message.
type Envelope struct {
	Bridge         string `json:"bridge"`
	Adapter        string `json:"adapter"`        // ax25 | acp127 | sbd
	Origin         string `json:"origin"`         // callsign / originator / IMEI
	Destination    string `json:"destination"`    // routed address
	Precedence     string `json:"precedence"`     // FLASH | IMMEDIATE | PRIORITY | ROUTINE
	Classification int    `json:"classification"` // 0..4
	HLC            int64  `json:"hlc"`            // hybrid logical clock (ms<<16 | counter)
	Body           string `json:"body"`
	Raw            []byte `json:"raw,omitempty"` // original frame for forensics
}

// Signed is an envelope with the bridge's composite signature.
type Signed struct {
	ID        string          `json:"id"`
	Envelope  json.RawMessage `json:"envelope"`
	Signature []byte          `json:"signature"`
}

// Sign canonicalises, content-addresses and signs an envelope.
func Sign(s cryptoprov.Signer, e Envelope) (Signed, error) {
	raw, err := json.Marshal(e)
	if err != nil {
		return Signed{}, err
	}
	sig, err := s.Sign(raw)
	if err != nil {
		return Signed{}, err
	}
	h := sha256.Sum256(raw)
	return Signed{ID: hex.EncodeToString(h[:]), Envelope: raw, Signature: sig}, nil
}

// Verify checks the content address and signature and returns the envelope.
func Verify(v cryptoprov.Verifier, pub []byte, s Signed) (*Envelope, error) {
	h := sha256.Sum256(s.Envelope)
	if hex.EncodeToString(h[:]) != s.ID {
		return nil, cryptoprov.ErrBadSignature
	}
	if err := v.Verify(pub, s.Envelope, s.Signature); err != nil {
		return nil, err
	}
	var e Envelope
	if err := json.Unmarshal(s.Envelope, &e); err != nil {
		return nil, err
	}
	return &e, nil
}

// HLC is a hybrid logical clock: monotonic even if the wall clock steps
// back, and it advances past any timestamp it observes.
type HLC struct {
	mu   sync.Mutex
	last int64
}

func (c *HLC) Now() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := time.Now().UnixMilli() << 16
	if t <= c.last {
		t = c.last + 1
	}
	c.last = t
	return t
}

func (c *HLC) Observe(remote int64) {
	c.mu.Lock()
	if remote > c.last {
		c.last = remote
	}
	c.mu.Unlock()
}

// Precedences in descending priority; used for QoS ordering of the spool.
var precedenceRank = map[string]int{"FLASH": 0, "IMMEDIATE": 1, "PRIORITY": 2, "ROUTINE": 3}

func Rank(p string) int {
	if r, ok := precedenceRank[p]; ok {
		return r
	}
	return 3
}
