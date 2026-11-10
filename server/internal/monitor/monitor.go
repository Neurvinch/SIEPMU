// Package monitor is the indigenous monitoring fabric: it consumes signed
// security telemetry from the SEC stream (platform services plus Wazuh,
// Suricata, Zeek and Falco sensors), persists it for SIEM search, runs
// ATT&CK-mapped correlation rules and per-user behavioural baselines
// (UEBA), opens incidents and executes SOAR containment playbooks.
package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/redis/go-redis/v9"

	"github.com/Neurvinch/SIEPMU/server/internal/audit"
	"github.com/Neurvinch/SIEPMU/server/internal/config"
	"github.com/Neurvinch/SIEPMU/server/internal/events"
	"github.com/Neurvinch/SIEPMU/server/internal/identity"
	"github.com/Neurvinch/SIEPMU/server/internal/store"
)

type Monitor struct {
	cfg     *config.Config
	db      *store.Store
	rdb     *redis.Client
	bus     *events.Bus
	id      *identity.Service
	audit   *audit.Log
	trusted map[string]bool
	export  *exporter

	mu sync.Mutex
}

func New(cfg *config.Config, db *store.Store, rdb *redis.Client, bus *events.Bus, id *identity.Service, al *audit.Log, trustedKeys [][]byte) *Monitor {
	t := map[string]bool{}
	for _, k := range trustedKeys {
		t[string(k)] = true
	}
	return &Monitor{cfg: cfg, db: db, rdb: rdb, bus: bus, id: id, audit: al, trusted: t, export: newExporter(cfg)}
}

// Run consumes the SEC stream with a durable consumer until ctx ends.
func (m *Monitor) Run(ctx context.Context) error {
	cons, err := m.bus.JS.CreateOrUpdateConsumer(ctx, "SEC", jetstream.ConsumerConfig{
		Durable:       "monitor",
		AckPolicy:     jetstream.AckExplicitPolicy,
		DeliverPolicy: jetstream.DeliverAllPolicy,
		MaxDeliver:    5,
		AckWait:       30 * time.Second,
	})
	if err != nil {
		return err
	}
	cc, err := cons.Consume(func(msg jetstream.Msg) {
		var e events.SecEvent
		if err := m.bus.Open(msg.Data(), func(k []byte) bool { return m.trusted[string(k)] }, &e); err != nil {
			fmt.Printf("monitor: dropping unverifiable event on %s: %v\n", msg.Subject(), err)
			msg.Term()
			return
		}
		if err := m.handle(ctx, e); err != nil {
			fmt.Printf("monitor: handle %s: %v\n", e.Kind, err)
			msg.Nak()
			return
		}
		msg.Ack()
	})
	if err != nil {
		return err
	}
	go m.runUEBAWindows(ctx)
	go m.export.run(ctx)
	<-ctx.Done()
	cc.Stop()
	return nil
}

func (m *Monitor) handle(ctx context.Context, e events.SecEvent) error {
	data, _ := json.Marshal(e.Data)
	if e.Data == nil {
		data = []byte("{}")
	}
	var uid *uuid.UUID
	if u, err := uuid.Parse(e.UserID); err == nil {
		uid = &u
	}
	if e.AttackIDs == nil {
		e.AttackIDs = []string{}
	}
	var id int64
	if err := m.db.QueryRow(ctx, `INSERT INTO sec_events(ts, source, kind, severity, user_id, ip, attack_ids, summary, data) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`,
		e.Time, e.Source, e.Kind, e.Severity, uid, nullable(e.IP), e.AttackIDs, e.Summary, data).Scan(&id); err != nil {
		return err
	}
	m.export.enqueue(id, e)
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.correlate(ctx, id, e)
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// slidingCount records an event in a Redis sorted set and returns how many
// occurred within the window, plus the member ids for incident evidence.
func (m *Monitor) slidingCount(ctx context.Context, key string, eventID int64, window time.Duration) (int, []int64, error) {
	now := time.Now()
	k := "corr:" + key
	pipe := m.rdb.TxPipeline()
	pipe.ZAdd(ctx, k, redis.Z{Score: float64(now.UnixMilli()), Member: strconv.FormatInt(eventID, 10)})
	pipe.ZRemRangeByScore(ctx, k, "-inf", strconv.FormatInt(now.Add(-window).UnixMilli(), 10))
	rng := pipe.ZRange(ctx, k, 0, -1)
	pipe.Expire(ctx, k, window+time.Minute)
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, nil, err
	}
	var ids []int64
	for _, s := range rng.Val() {
		if v, err := strconv.ParseInt(s, 10, 64); err == nil {
			ids = append(ids, v)
		}
	}
	return len(ids), ids, nil
}

// AddRisk adds decaying risk points for a user and republishes the score the
// identity ring feeds into policy decisions.
func (m *Monitor) AddRisk(ctx context.Context, user string, points int, reason string) int {
	if user == "" {
		return 0
	}
	now := time.Now()
	k := "riskpts:" + user
	member := fmt.Sprintf("%d:%d:%s", now.UnixNano(), points, reason)
	m.rdb.ZAdd(ctx, k, redis.Z{Score: float64(now.Unix()), Member: member})
	m.rdb.Expire(ctx, k, 25*time.Hour)
	return m.recomputeRisk(ctx, user)
}

// recomputeRisk: each contribution decays linearly to zero over 24 hours.
func (m *Monitor) recomputeRisk(ctx context.Context, user string) int {
	k := "riskpts:" + user
	now := time.Now()
	m.rdb.ZRemRangeByScore(ctx, k, "-inf", strconv.FormatInt(now.Add(-24*time.Hour).Unix(), 10))
	zs, _ := m.rdb.ZRangeWithScores(ctx, k, 0, -1).Result()
	total := 0.0
	for _, z := range zs {
		var ns, pts int64
		fmt.Sscanf(z.Member.(string), "%d:%d:", &ns, &pts)
		age := now.Sub(time.Unix(int64(z.Score), 0)).Hours()
		total += float64(pts) * (1 - age/24)
	}
	score := int(total + 0.5)
	if score > 100 {
		score = 100
	}
	if score < 0 {
		score = 0
	}
	m.rdb.Set(ctx, "risk:"+user, score, 25*time.Hour)
	return score
}
