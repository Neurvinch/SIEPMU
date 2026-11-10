package monitor

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Neurvinch/SIEPMU/server/internal/events"
)

// UEBA keeps a running mean/variance (Welford) per user and feature. An
// observation more than 3 standard deviations above a baseline built from at
// least minSamples observations is published as a ueba.anomaly event.
const (
	minSamples = 10
	zThreshold = 3.0
)

// observe updates the baseline and returns the z-score of x against the
// baseline as it stood before this observation.
func (m *Monitor) observe(ctx context.Context, user uuid.UUID, feature string, x float64) (z float64, n int64, err error) {
	tx, err := m.db.Begin(ctx)
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback(ctx)
	var mean, m2 float64
	err = tx.QueryRow(ctx, `SELECT mean, m2, n FROM ueba_baselines WHERE user_id=$1 AND feature=$2 FOR UPDATE`, user, feature).Scan(&mean, &m2, &n)
	if err != nil {
		n, mean, m2 = 0, 0, 0
	}
	if n >= 2 {
		sd := math.Sqrt(m2 / float64(n-1))
		if sd < 1 {
			sd = 1 // floor: avoids alerting on tiny deviations from a flat baseline
		}
		z = (x - mean) / sd
	}
	prevN := n
	n++
	d := x - mean
	mean += d / float64(n)
	m2 += d * (x - mean)
	if _, err := tx.Exec(ctx, `INSERT INTO ueba_baselines(user_id, feature, mean, m2, n) VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (user_id, feature) DO UPDATE SET mean=EXCLUDED.mean, m2=EXCLUDED.m2, n=EXCLUDED.n, updated_at=now()`, user, feature, mean, m2, n); err != nil {
		return 0, 0, err
	}
	return z, prevN, tx.Commit(ctx)
}

// uebaLoginHour flags logins at an hour far from the user's usual pattern.
// Hours are compared on a circle so 23:00 and 01:00 are two hours apart.
func (m *Monitor) uebaLoginHour(ctx context.Context, eventID int64, e events.SecEvent) {
	u, err := uuid.Parse(e.UserID)
	if err != nil {
		return
	}
	h := float64(e.Time.UTC().Hour()) + float64(e.Time.UTC().Minute())/60
	var mean float64
	var n int64
	m.db.QueryRow(ctx, `SELECT mean, n FROM ueba_baselines WHERE user_id=$1 AND feature='login_hour'`, u).Scan(&mean, &n)
	// Unwrap onto the half-day around the current mean before updating.
	x := h
	if n > 0 {
		if x-mean > 12 {
			x -= 24
		} else if mean-x > 12 {
			x += 24
		}
	}
	z, prevN, err := m.observe(ctx, u, "login_hour", x)
	if err != nil || prevN < minSamples || math.Abs(z) < zThreshold {
		return
	}
	m.publishAnomaly(ctx, e.UserID, e.IP, "login_hour", fmt.Sprintf("login at %02d:%02d UTC is %.1fσ from this user's usual hours", e.Time.UTC().Hour(), e.Time.UTC().Minute(), math.Abs(z)), z, []string{"T1078"})
}

func (m *Monitor) publishAnomaly(ctx context.Context, user, ip, feature, summary string, z float64, attack []string) {
	m.AddRisk(ctx, user, 20, "ueba:"+feature)
	m.bus.PublishSec(ctx, events.SecEvent{Source: "ueba", Kind: "ueba.anomaly", Severity: 2, UserID: user, IP: ip, AttackIDs: attack,
		Summary: summary, Data: map[string]any{"feature": feature, "z": math.Round(z*10) / 10}})
}

// runUEBAWindows closes 15-minute activity windows: per-user download
// counts are compared with the user's baseline and then folded into it.
func (m *Monitor) runUEBAWindows(ctx context.Context) {
	t := time.NewTicker(15 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.closeWindow(ctx)
		}
	}
}

func (m *Monitor) closeWindow(ctx context.Context) {
	const prefix = "ueba:win:downloads:"
	iter := m.rdb.Scan(ctx, 0, prefix+"*", 500).Iterator()
	for iter.Next(ctx) {
		key := iter.Val()
		v, err := m.rdb.GetDel(ctx, key).Result()
		if err != nil {
			continue
		}
		count, _ := strconv.ParseFloat(v, 64)
		user := strings.TrimPrefix(key, prefix)
		u, err := uuid.Parse(user)
		if err != nil {
			continue
		}
		z, prevN, err := m.observe(ctx, u, "downloads_15m", count)
		if err == nil && prevN >= minSamples && z >= zThreshold {
			m.publishAnomaly(ctx, user, "", "downloads_15m", fmt.Sprintf("%.0f downloads in 15 min is %.1fσ above this user's baseline", count, z), z, []string{"T1530"})
		}
	}
}
