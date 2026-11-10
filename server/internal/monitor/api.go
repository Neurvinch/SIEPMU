package monitor

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Neurvinch/SIEPMU/server/internal/audit"
	"github.com/Neurvinch/SIEPMU/server/internal/httpx"
	"github.com/Neurvinch/SIEPMU/server/internal/identity"
	"github.com/Neurvinch/SIEPMU/server/internal/policy"
)

func (m *Monitor) authz(w http.ResponseWriter, r *http.Request, res policy.Resource, action string) bool {
	if err := m.id.Authorize(r, res, action); err != nil {
		httpx.Fail(w, err)
		return false
	}
	return true
}

// ------------------------------------------------------------------ SOC

func (m *Monitor) handleEvents(w http.ResponseWriter, r *http.Request) {
	if !m.authz(w, r, policy.Resource{Type: "soc"}, "read") {
		return
	}
	q := r.URL.Query()
	minSev, _ := strconv.Atoi(q.Get("min_severity"))
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
	if before == 0 {
		before = 1 << 62
	}
	rows, err := m.db.Query(r.Context(), `SELECT e.id, e.ts, e.source, e.kind, e.severity, e.user_id, coalesce(e.ip,''), e.attack_ids, e.summary, e.data, coalesce(u.service_number,'')
		FROM sec_events e LEFT JOIN users u ON u.id=e.user_id
		WHERE e.id < $1 AND e.severity >= $2 AND ($3='' OR e.source=$3) AND ($4='' OR e.kind LIKE $4 || '%')
		  AND ($5='' OR e.summary ILIKE '%'||$5||'%' OR e.ip=$5 OR u.service_number=$5 OR $5 = ANY(e.attack_ids))
		ORDER BY e.id DESC LIMIT $6`, before, minSev, q.Get("source"), q.Get("kind"), strings.TrimSpace(q.Get("q")), limit)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id int64
		var ts time.Time
		var src, kind, ip, summary, sn string
		var sev int
		var uid *uuid.UUID
		var att []string
		var data json.RawMessage
		if err := rows.Scan(&id, &ts, &src, &kind, &sev, &uid, &ip, &att, &summary, &data, &sn); err != nil {
			httpx.Fail(w, err)
			return
		}
		out = append(out, map[string]any{"id": id, "time": ts, "source": src, "kind": kind, "severity": sev, "user_id": uid, "service_number": sn, "ip": ip, "attack_ids": att, "summary": summary, "data": data})
	}
	httpx.JSON(w, 200, out)
}

func (m *Monitor) handleIncidents(w http.ResponseWriter, r *http.Request) {
	if !m.authz(w, r, policy.Resource{Type: "soc"}, "read") {
		return
	}
	st := r.URL.Query().Get("status")
	rows, err := m.db.Query(r.Context(), `SELECT i.id, i.rule_id, i.title, i.attack_ids, i.severity, i.status, i.user_id, coalesce(u.rank||' '||u.full_name,''), coalesce(i.ip,''), coalesce(i.unit_code,''), i.event_ids, i.actions, i.assignee_id, i.notes, i.created_at, i.updated_at
		FROM incidents i LEFT JOIN users u ON u.id=i.user_id WHERE ($1='' OR i.status=$1) ORDER BY (i.status='open') DESC, i.severity DESC, i.created_at DESC LIMIT 300`, st)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id uuid.UUID
		var rule, title, status, subject, ip, unit, notes string
		var att []string
		var sev int
		var uid, assignee *uuid.UUID
		var evs []int64
		var actions json.RawMessage
		var c, u time.Time
		if err := rows.Scan(&id, &rule, &title, &att, &sev, &status, &uid, &subject, &ip, &unit, &evs, &actions, &assignee, &notes, &c, &u); err != nil {
			httpx.Fail(w, err)
			return
		}
		out = append(out, map[string]any{"id": id, "rule": rule, "title": title, "attack_ids": att, "severity": sev, "status": status, "user_id": uid, "subject": subject, "ip": ip, "unit": unit,
			"event_ids": evs, "actions": actions, "assignee_id": assignee, "notes": notes, "created_at": c, "updated_at": u})
	}
	httpx.JSON(w, 200, out)
}

func (m *Monitor) handleUpdateIncident(w http.ResponseWriter, r *http.Request) {
	if !m.authz(w, r, policy.Resource{Type: "soc"}, "manage") {
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Fail(w, httpx.E(400, "bad_request", "bad id"))
		return
	}
	var req struct {
		Status *string `json:"status"`
		Notes  *string `json:"notes"`
		Assign bool    `json:"assign_to_me"`
	}
	if err := httpx.Decode(r, 16<<10, &req); err != nil {
		httpx.Fail(w, err)
		return
	}
	p := identity.FromContext(r.Context())
	if req.Status != nil {
		switch *req.Status {
		case "open", "contained", "resolved", "false_positive":
		default:
			httpx.Fail(w, httpx.E(400, "bad_request", "invalid status"))
			return
		}
		if _, err := m.db.Exec(r.Context(), `UPDATE incidents SET status=$2, updated_at=now() WHERE id=$1`, id, *req.Status); err != nil {
			httpx.Fail(w, httpx.E(409, "conflict", "another open incident has the same correlation key"))
			return
		}
	}
	if req.Notes != nil {
		m.db.Exec(r.Context(), `UPDATE incidents SET notes=$2, updated_at=now() WHERE id=$1`, id, *req.Notes)
	}
	if req.Assign {
		m.db.Exec(r.Context(), `UPDATE incidents SET assignee_id=$2, updated_at=now() WHERE id=$1`, id, p.User.ID)
	}
	m.audit.Record(r.Context(), audit.Entry{Actor: p.User.ID.String(), Action: "soc.incident.update", Resource: id.String(), Outcome: "success", IP: p.IP,
		Details: map[string]any{"status": req.Status, "assigned": req.Assign}})
	w.WriteHeader(204)
}

func (m *Monitor) handleBlocked(w http.ResponseWriter, r *http.Request) {
	if !m.authz(w, r, policy.Resource{Type: "soc"}, "read") {
		return
	}
	rows, err := m.db.Query(r.Context(), `SELECT ip, reason, created_at, expires_at FROM blocked_ips WHERE expires_at > now() ORDER BY created_at DESC`)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var ip, reason string
		var c, e time.Time
		rows.Scan(&ip, &reason, &c, &e)
		out = append(out, map[string]any{"ip": ip, "reason": reason, "created_at": c, "expires_at": e})
	}
	httpx.JSON(w, 200, out)
}

func (m *Monitor) handleUnblock(w http.ResponseWriter, r *http.Request) {
	if !m.authz(w, r, policy.Resource{Type: "soc"}, "manage") {
		return
	}
	var req struct {
		IP string `json:"ip"`
	}
	if err := httpx.Decode(r, 1024, &req); err != nil {
		httpx.Fail(w, err)
		return
	}
	m.db.Exec(r.Context(), `DELETE FROM blocked_ips WHERE ip=$1`, req.IP)
	m.bus.NC.Publish("siepmu.ctl.blocklist", nil)
	p := identity.FromContext(r.Context())
	m.audit.Record(r.Context(), audit.Entry{Actor: p.User.ID.String(), Action: "soc.ip.unblock", Resource: req.IP, Outcome: "success", IP: p.IP})
	w.WriteHeader(204)
}

func (m *Monitor) handleSOCSummary(w http.ResponseWriter, r *http.Request) {
	if !m.authz(w, r, policy.Resource{Type: "soc"}, "read") {
		return
	}
	ctx := r.Context()
	out := map[string]any{}
	var open, contained, ev24, sessions int
	m.db.QueryRow(ctx, `SELECT count(*) FILTER (WHERE status='open'), count(*) FILTER (WHERE status='contained') FROM incidents`).Scan(&open, &contained)
	m.db.QueryRow(ctx, `SELECT count(*) FROM sec_events WHERE ts > now() - interval '24 hours'`).Scan(&ev24)
	m.db.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE revoked_at IS NULL AND expires_at > now()`).Scan(&sessions)
	out["open_incidents"], out["contained_incidents"], out["events_24h"], out["active_sessions"] = open, contained, ev24, sessions
	// ATT&CK technique frequency over the last 7 days.
	rows, err := m.db.Query(ctx, `SELECT t, count(*) FROM sec_events, unnest(attack_ids) t WHERE ts > now() - interval '7 days' GROUP BY t ORDER BY 2 DESC LIMIT 20`)
	if err == nil {
		att := []map[string]any{}
		for rows.Next() {
			var t string
			var n int
			rows.Scan(&t, &n)
			att = append(att, map[string]any{"technique": t, "count": n})
		}
		rows.Close()
		out["attack_techniques_7d"] = att
	}
	rows, err = m.db.Query(ctx, `SELECT date_trunc('hour', ts) h, count(*), count(*) FILTER (WHERE severity>=3) FROM sec_events WHERE ts > now() - interval '24 hours' GROUP BY h ORDER BY h`)
	if err == nil {
		tl := []map[string]any{}
		for rows.Next() {
			var h time.Time
			var n, hi int
			rows.Scan(&h, &n, &hi)
			tl = append(tl, map[string]any{"hour": h, "events": n, "high": hi})
		}
		rows.Close()
		out["timeline_24h"] = tl
	}
	rows, err = m.db.Query(ctx, `SELECT source, count(*) FROM sec_events WHERE ts > now() - interval '24 hours' GROUP BY source ORDER BY 2 DESC`)
	if err == nil {
		src := []map[string]any{}
		for rows.Next() {
			var s string
			var n int
			rows.Scan(&s, &n)
			src = append(src, map[string]any{"source": s, "count": n})
		}
		rows.Close()
		out["sources_24h"] = src
	}
	httpx.JSON(w, 200, out)
}

// ------------------------------------------------------------------ commander

func (m *Monitor) handleUnitHealth(w http.ResponseWriter, r *http.Request) {
	p := identity.FromContext(r.Context())
	unit := p.User.Unit
	if !m.authz(w, r, policy.Resource{Type: "unit", Unit: unit}, "read") {
		return
	}
	ctx := r.Context()
	out := map[string]any{"unit": unit}
	var total, active, pending, suspended, online, devPending, incOpen, bgPending, channels int
	m.db.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE status='active'), count(*) FILTER (WHERE status='pending'), count(*) FILTER (WHERE status='suspended') FROM users WHERE unit_code=$1`, unit).Scan(&total, &active, &pending, &suspended)
	m.db.QueryRow(ctx, `SELECT count(DISTINCT s.user_id) FROM sessions s JOIN users u ON u.id=s.user_id WHERE u.unit_code=$1 AND s.revoked_at IS NULL AND s.last_active_at > now() - interval '15 minutes'`, unit).Scan(&online)
	m.db.QueryRow(ctx, `SELECT count(*) FROM devices d JOIN users u ON u.id=d.user_id WHERE u.unit_code=$1 AND d.status='pending'`, unit).Scan(&devPending)
	m.db.QueryRow(ctx, `SELECT count(*) FROM incidents WHERE unit_code=$1 AND status='open'`, unit).Scan(&incOpen)
	m.db.QueryRow(ctx, `SELECT count(*) FROM breakglass_requests b JOIN users u ON u.id=b.requester_id WHERE u.unit_code=$1 AND b.status='pending'`, unit).Scan(&bgPending)
	m.db.QueryRow(ctx, `SELECT count(*) FROM channels WHERE unit_code=$1`, unit).Scan(&channels)
	out["personnel"] = map[string]int{"total": total, "active": active, "pending_enrolment": pending, "suspended": suspended, "online_15m": online}
	out["devices_pending"], out["open_incidents"], out["breakglass_pending"], out["channels"] = devPending, incOpen, bgPending, channels
	rows, err := m.db.Query(ctx, `SELECT u.id, u.service_number, u.rank, u.full_name, u.status, u.clearance,
		(SELECT max(last_active_at) FROM sessions s WHERE s.user_id=u.id), (SELECT count(*) FROM incidents i WHERE i.user_id=u.id AND i.status='open')
		FROM users u WHERE u.unit_code=$1 ORDER BY u.service_number`, unit)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	people := []map[string]any{}
	type pr struct {
		id uuid.UUID
		m  map[string]any
	}
	var prs []pr
	for rows.Next() {
		var id uuid.UUID
		var sn, rank, name, status string
		var cl, inc int
		var last *time.Time
		rows.Scan(&id, &sn, &rank, &name, &status, &cl, &last, &inc)
		prs = append(prs, pr{id, map[string]any{"id": id, "service_number": sn, "rank": rank, "name": name, "status": status, "clearance": cl, "last_active": last, "open_incidents": inc}})
	}
	rows.Close()
	for _, x := range prs {
		risk, _ := m.rdb.Get(ctx, "risk:"+x.id.String()).Int()
		x.m["risk"] = risk
		people = append(people, x.m)
	}
	out["people"] = people
	rows, err = m.db.Query(ctx, `SELECT id, title, severity, status, created_at FROM incidents WHERE unit_code=$1 ORDER BY created_at DESC LIMIT 20`, unit)
	if err == nil {
		incs := []map[string]any{}
		for rows.Next() {
			var id uuid.UUID
			var title, st string
			var sev int
			var c time.Time
			rows.Scan(&id, &title, &sev, &st, &c)
			incs = append(incs, map[string]any{"id": id, "title": title, "severity": sev, "status": st, "created_at": c})
		}
		rows.Close()
		out["recent_incidents"] = incs
	}
	httpx.JSON(w, 200, out)
}

// ------------------------------------------------------------------ auditor

func (m *Monitor) handleAuditHead(w http.ResponseWriter, r *http.Request) {
	if !m.authz(w, r, policy.Resource{Type: "audit"}, "read") {
		return
	}
	th, err := m.audit.SignHead(r.Context())
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	httpx.JSON(w, 200, th)
}

func (m *Monitor) handleAuditEntries(w http.ResponseWriter, r *http.Request) {
	if !m.authz(w, r, policy.Resource{Type: "audit"}, "read") {
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	before, _ := strconv.ParseInt(q.Get("before"), 10, 64)
	if before == 0 {
		before = 1 << 62
	}
	rows, err := m.db.Query(r.Context(), `SELECT idx, entry_raw, leaf_hash FROM audit_leaves
		WHERE idx < $1 AND ($2='' OR entry->>'action' LIKE $2||'%') AND ($3='' OR entry->>'actor'=$3 OR entry->>'resource'=$3)
		ORDER BY idx DESC LIMIT $4`, before, q.Get("action"), q.Get("q"), limit)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var idx int64
		var raw json.RawMessage
		var lh []byte
		rows.Scan(&idx, &raw, &lh)
		out = append(out, map[string]any{"index": idx, "entry": raw, "leaf_hash": lh})
	}
	httpx.JSON(w, 200, out)
}

func (m *Monitor) handleAuditProof(w http.ResponseWriter, r *http.Request) {
	if !m.authz(w, r, policy.Resource{Type: "audit"}, "read") {
		return
	}
	idx, err1 := audit.ParseIndex(r.PathValue("index"))
	size, err2 := audit.ParseIndex(r.URL.Query().Get("tree_size"))
	if err1 != nil || err2 != nil {
		httpx.Fail(w, httpx.E(400, "bad_request", "index and tree_size are required"))
		return
	}
	p, err := m.audit.InclusionProof(r.Context(), idx, size)
	if err != nil {
		httpx.Fail(w, httpx.E(400, "bad_request", err.Error()))
		return
	}
	httpx.JSON(w, 200, p)
}

func (m *Monitor) handleAuditConsistency(w http.ResponseWriter, r *http.Request) {
	if !m.authz(w, r, policy.Resource{Type: "audit"}, "read") {
		return
	}
	a, err1 := audit.ParseIndex(r.URL.Query().Get("first"))
	b, err2 := audit.ParseIndex(r.URL.Query().Get("second"))
	if err1 != nil || err2 != nil || a > b {
		httpx.Fail(w, httpx.E(400, "bad_request", "first <= second required"))
		return
	}
	p, err := m.audit.ConsistencyProof(r.Context(), a, b)
	if err != nil {
		httpx.Fail(w, httpx.E(400, "bad_request", err.Error()))
		return
	}
	var r1, r2 []byte
	m.db.QueryRow(r.Context(), `SELECT root_hash FROM audit_tree_heads WHERE size=$1`, int64(a)).Scan(&r1)
	m.db.QueryRow(r.Context(), `SELECT root_hash FROM audit_tree_heads WHERE size=$1`, int64(b)).Scan(&r2)
	httpx.JSON(w, 200, map[string]any{"first": a, "second": b, "proof": p, "first_root": r1, "second_root": r2})
}

func (m *Monitor) handleAuditHeads(w http.ResponseWriter, r *http.Request) {
	if !m.authz(w, r, policy.Resource{Type: "audit"}, "read") {
		return
	}
	rows, err := m.db.Query(r.Context(), `SELECT size, root_hash, ts, signature FROM audit_tree_heads ORDER BY size DESC LIMIT 50`)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var size int64
		var root, sig []byte
		var ts time.Time
		rows.Scan(&size, &root, &ts, &sig)
		out = append(out, map[string]any{"size": size, "root_hash": root, "time": ts.UTC(), "signature": sig})
	}
	httpx.JSON(w, 200, out)
}

func (m *Monitor) Routes(mux *http.ServeMux, auth func(http.HandlerFunc) http.Handler) {
	mux.Handle("GET /api/soc/summary", auth(m.handleSOCSummary))
	mux.Handle("GET /api/soc/events", auth(m.handleEvents))
	mux.Handle("GET /api/soc/incidents", auth(m.handleIncidents))
	mux.Handle("PATCH /api/soc/incidents/{id}", auth(m.handleUpdateIncident))
	mux.Handle("GET /api/soc/blocked", auth(m.handleBlocked))
	mux.Handle("POST /api/soc/unblock", auth(m.handleUnblock))
	mux.Handle("GET /api/commander/unit", auth(m.handleUnitHealth))
	mux.Handle("GET /api/audit/head", auth(m.handleAuditHead))
	mux.Handle("GET /api/audit/heads", auth(m.handleAuditHeads))
	mux.Handle("GET /api/audit/entries", auth(m.handleAuditEntries))
	mux.Handle("GET /api/audit/proof/{index}", auth(m.handleAuditProof))
	mux.Handle("GET /api/audit/consistency", auth(m.handleAuditConsistency))
}
