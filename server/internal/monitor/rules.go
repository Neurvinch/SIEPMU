package monitor

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"

	"github.com/Neurvinch/SIEPMU/server/internal/audit"
	"github.com/Neurvinch/SIEPMU/server/internal/events"
	"github.com/Neurvinch/SIEPMU/server/internal/identity"
)

//go:embed playbooks.yaml
var playbookYAML []byte

var playbooks = func() map[string][]string {
	m := map[string][]string{}
	if err := yaml.Unmarshal(playbookYAML, &m); err != nil {
		panic(err)
	}
	return m
}()

type finding struct {
	rule     string
	title    string
	attack   []string
	severity int
	user     string
	ip       string
	dedup    string
	events   []int64
}

// correlate evaluates every rule for one event.
func (m *Monitor) correlate(ctx context.Context, id int64, e events.SecEvent) error {
	var fs []finding
	add := func(f finding) { fs = append(fs, f) }
	switch e.Kind {
	case "auth.webauthn_failure", "auth.enroll_failure", "auth.unknown_user":
		key := e.UserID
		if key == "" {
			key = e.IP
		}
		if n, ids, err := m.slidingCount(ctx, "bf:"+key, id, 10*time.Minute); err == nil && n >= 5 {
			add(finding{rule: "brute_force_auth", title: fmt.Sprintf("%d failed FIDO2/enrolment attempts in 10 min", n), attack: []string{"T1110"}, severity: 3, user: e.UserID, ip: e.IP, dedup: "bf:" + key, events: ids})
		}
	case "auth.login_success":
		if f, ok := impossibleTravel(e); ok {
			f.events = []int64{id}
			add(f)
		}
		m.uebaLoginHour(ctx, id, e)
	case "policy.deny":
		if n, ids, err := m.slidingCount(ctx, "deny:"+e.UserID, id, 5*time.Minute); err == nil && n >= 10 {
			add(finding{rule: "policy_probe", title: fmt.Sprintf("%d policy denials in 5 min (access probing)", n), attack: []string{"T1083", "T1069"}, severity: 2, user: e.UserID, ip: e.IP, dedup: "deny:" + e.UserID, events: ids})
		}
	case "file.download":
		n, ids, err := m.slidingCount(ctx, "dl:"+e.UserID, id, 10*time.Minute)
		bytesKey := "dlbytes:" + e.UserID
		b, _ := toInt64(e.Data["bytes"])
		total, _ := m.rdb.IncrBy(ctx, bytesKey, b).Result()
		m.rdb.ExpireNX(ctx, bytesKey, 10*time.Minute)
		if err == nil && (n >= 20 || total > 500<<20) {
			add(finding{rule: "bulk_export", title: fmt.Sprintf("bulk export: %d files / %d MiB in 10 min", n, total>>20), attack: []string{"T1530", "T1567"}, severity: 3, user: e.UserID, ip: e.IP, dedup: "dl:" + e.UserID, events: ids})
		}
		m.rdb.Incr(ctx, "ueba:win:downloads:"+e.UserID)
		m.rdb.Expire(ctx, "ueba:win:downloads:"+e.UserID, 30*time.Minute)
	case "hsm.unwrap_failure":
		if n, ids, err := m.slidingCount(ctx, "hsmfail", id, 5*time.Minute); err == nil && n >= 3 {
			add(finding{rule: "hsm_unwrap_burst", title: fmt.Sprintf("%d HSM unwrap failures in 5 min", n), attack: []string{"T1552"}, severity: 4, user: e.UserID, ip: e.IP, dedup: "hsmfail", events: ids})
		}
	case "auth.refresh_reuse", "auth.authenticator_clone", "device.key_reuse":
		add(finding{rule: "credential_compromise", title: e.Summary, attack: e.AttackIDs, severity: 4, user: e.UserID, ip: e.IP, dedup: e.Kind + ":" + e.UserID, events: []int64{id}})
	case "gateway.rate_limited":
		if n, ids, err := m.slidingCount(ctx, "rl:"+e.IP, id, 5*time.Minute); err == nil && n >= 5 {
			add(finding{rule: "gateway_flood", title: "sustained rate-limit violations from " + e.IP, attack: []string{"T1499"}, severity: 2, ip: e.IP, dedup: "rl:" + e.IP, events: ids})
		}
	case "identity.privilege_change":
		add(finding{rule: "privilege_change", title: e.Summary, attack: []string{"T1098"}, severity: 2, user: e.UserID, ip: e.IP, dedup: fmt.Sprintf("priv:%d", id), events: []int64{id}})
	case "breakglass.activated":
		add(finding{rule: "breakglass_activation", title: "break-glass elevation active: post-review required", attack: []string{"T1078"}, severity: 2, user: e.UserID, ip: e.IP, dedup: fmt.Sprintf("bg:%v", e.Data["request_id"]), events: []int64{id}})
	case "file.integrity_violation":
		add(finding{rule: "file_integrity", title: e.Summary, attack: []string{"T1565"}, severity: 3, user: e.UserID, ip: e.IP, dedup: fmt.Sprintf("fi:%v", e.Data["file"]), events: []int64{id}})
	case "bridge.rejected":
		if n, ids, err := m.slidingCount(ctx, "bridge_rej", id, 10*time.Minute); err == nil && n >= 5 {
			add(finding{rule: "bridge_rejects", title: fmt.Sprintf("%d legacy messages rejected by the content-validation gate in 10 min", n), attack: []string{"T1027"}, severity: 2, dedup: "bridge_rej", events: ids})
		}
	}
	if strings.HasPrefix(e.Kind, "sensor.") && e.Severity >= 3 {
		rule := "sensor_high"
		if e.Severity >= 4 {
			rule = "sensor_critical"
		}
		add(finding{rule: rule, title: e.Source + ": " + e.Summary, attack: e.AttackIDs, severity: e.Severity, user: e.UserID, ip: e.IP, dedup: e.Source + ":" + e.Summary + ":" + e.IP, events: []int64{id}})
	}
	if e.Kind == "ueba.anomaly" {
		add(finding{rule: "ueba_anomaly", title: e.Summary, attack: e.AttackIDs, severity: e.Severity, user: e.UserID, ip: e.IP, dedup: fmt.Sprintf("ueba:%s:%v", e.UserID, e.Data["feature"]), events: []int64{id}})
	}
	for _, f := range fs {
		if err := m.openIncident(ctx, f); err != nil {
			return err
		}
	}
	return nil
}

func toInt64(v any) (int64, bool) {
	switch x := v.(type) {
	case float64:
		return int64(x), true
	case int64:
		return x, true
	case int:
		return int64(x), true
	case json.Number:
		i, err := x.Int64()
		return i, err == nil
	}
	return 0, false
}

func impossibleTravel(e events.SecEvent) (finding, bool) {
	lat, ok1 := e.Data["lat"].(float64)
	lon, ok2 := e.Data["lon"].(float64)
	plat, ok3 := e.Data["prev_lat"].(float64)
	plon, ok4 := e.Data["prev_lon"].(float64)
	pts, ok5 := e.Data["prev_time"].(string)
	if !(ok1 && ok2 && ok3 && ok4 && ok5) {
		return finding{}, false
	}
	prev, err := time.Parse(time.RFC3339, pts)
	if err != nil {
		return finding{}, false
	}
	km := identity.HaversineKm(plat, plon, lat, lon)
	hours := e.Time.Sub(prev).Hours()
	if hours < 1.0/60 {
		hours = 1.0 / 60
	}
	speed := km / hours
	if km > 100 && speed > 900 { // faster than a commercial airliner
		return finding{rule: "impossible_travel", title: fmt.Sprintf("impossible travel: %.0f km in %.1f h (%.0f km/h)", km, hours, speed),
			attack: []string{"T1078"}, severity: 3, user: e.UserID, ip: e.IP, dedup: "travel:" + e.UserID}, true
	}
	return finding{}, false
}

// openIncident creates (or extends) an incident and runs its playbook once.
func (m *Monitor) openIncident(ctx context.Context, f finding) error {
	var uid *uuid.UUID
	var unit string
	if u, err := uuid.Parse(f.user); err == nil {
		uid = &u
		m.db.QueryRow(ctx, `SELECT unit_code FROM users WHERE id=$1`, u).Scan(&unit)
	}
	if f.attack == nil {
		f.attack = []string{}
	}
	id := uuid.New()
	tag, err := m.db.Exec(ctx, `INSERT INTO incidents(id, rule_id, title, attack_ids, severity, user_id, ip, unit_code, event_ids, dedup_key)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT (dedup_key) WHERE status='open' DO UPDATE SET event_ids = (
			SELECT array_agg(DISTINCT e) FROM unnest(incidents.event_ids || EXCLUDED.event_ids) e), updated_at=now(), title=EXCLUDED.title
		RETURNING (xmax = 0)`, id, f.rule, f.title, f.attack, f.severity, uid, nullable(f.ip), nullable(unit), f.events, f.dedup)
	_ = tag
	if err != nil {
		return err
	}
	var inserted bool
	var incID uuid.UUID
	if err := m.db.QueryRow(ctx, `SELECT id, created_at = updated_at FROM incidents WHERE dedup_key=$1 AND status='open'`, f.dedup).Scan(&incID, &inserted); err != nil {
		return err
	}
	if !inserted {
		return nil // existing open incident extended; playbook already ran
	}
	m.audit.Record(ctx, audit.Entry{Actor: "monitor", Action: "soc.incident.open", Resource: incID.String(), Outcome: "success", IP: f.ip,
		Details: map[string]any{"rule": f.rule, "attack": f.attack, "severity": f.severity, "user": f.user}})
	return m.runPlaybook(ctx, incID, f, unit)
}

type actionResult struct {
	Action string    `json:"action"`
	Result string    `json:"result"`
	At     time.Time `json:"at"`
}

func (m *Monitor) runPlaybook(ctx context.Context, incID uuid.UUID, f finding, unit string) error {
	var results []actionResult
	rec := func(a, r string) { results = append(results, actionResult{a, r, time.Now().UTC()}) }
	for _, step := range playbooks[f.rule] {
		parts := strings.Fields(step)
		switch parts[0] {
		case "block_ip":
			if f.ip == "" {
				rec(step, "skipped: no source IP")
				continue
			}
			d, err := time.ParseDuration(parts[1])
			if err != nil {
				rec(step, "bad duration")
				continue
			}
			if _, err := m.db.Exec(ctx, `INSERT INTO blocked_ips(ip, reason, incident_id, expires_at) VALUES ($1,$2,$3,$4) ON CONFLICT (ip) DO UPDATE SET expires_at=GREATEST(blocked_ips.expires_at, EXCLUDED.expires_at), reason=EXCLUDED.reason`,
				f.ip, f.title, incID, time.Now().Add(d)); err != nil {
				rec(step, "error: "+err.Error())
				continue
			}
			m.bus.NC.Publish("siepmu.ctl.blocklist", nil)
			rec(step, "blocked "+f.ip+" for "+d.String())
		case "revoke_sessions":
			u, err := uuid.Parse(f.user)
			if err != nil {
				rec(step, "skipped: no subject")
				continue
			}
			n, err := m.id.RevokeUserSessions(ctx, u, "SOAR: "+f.rule)
			if err != nil {
				rec(step, "error: "+err.Error())
				continue
			}
			rec(step, fmt.Sprintf("revoked %d session(s)", n))
		case "raise_risk":
			pts, _ := strconv.Atoi(parts[1])
			if f.user == "" {
				rec(step, "skipped: no subject")
				continue
			}
			rec(step, fmt.Sprintf("risk now %d", m.AddRisk(ctx, f.user, pts, f.rule)))
		case "notify":
			role := parts[1]
			scope := ""
			if role == "commander" {
				scope = unit
				if scope == "" {
					rec(step, "skipped: subject has no unit")
					continue
				}
			}
			m.id.NotifyRole(ctx, role, scope, "incident", fmt.Sprintf("[SEV%d] %s", f.severity, f.title), incID.String())
			rec(step, "notified "+role)
		case "webhook":
			if m.cfg.Monitor.WebhookURL == "" {
				rec(step, "skipped: no webhook configured")
				continue
			}
			body, _ := json.Marshal(map[string]any{"incident": incID, "rule": f.rule, "title": f.title, "severity": f.severity, "attack": f.attack, "user": f.user, "ip": f.ip, "unit": unit})
			req, _ := http.NewRequestWithContext(ctx, http.MethodPost, m.cfg.Monitor.WebhookURL, bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
			if err != nil {
				rec(step, "error: "+err.Error())
				continue
			}
			resp.Body.Close()
			rec(step, "webhook "+resp.Status)
		}
	}
	rj, _ := json.Marshal(results)
	status := "open"
	for _, r := range results {
		if (strings.HasPrefix(r.Action, "block_ip") && strings.HasPrefix(r.Result, "blocked")) || (r.Action == "revoke_sessions" && strings.HasPrefix(r.Result, "revoked")) {
			status = "contained"
		}
	}
	_, err := m.db.Exec(ctx, `UPDATE incidents SET actions=$2, status=$3, updated_at=now() WHERE id=$1`, incID, rj, status)
	if err == nil && len(results) > 0 {
		m.audit.Record(ctx, audit.Entry{Actor: "soar", Action: "soc.playbook." + f.rule, Resource: incID.String(), Outcome: "success", Details: map[string]any{"actions": results}})
	}
	return err
}
