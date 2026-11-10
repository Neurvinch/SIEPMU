package identity

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Neurvinch/SIEPMU/server/internal/audit"
	"github.com/Neurvinch/SIEPMU/server/internal/httpx"
	"github.com/Neurvinch/SIEPMU/server/internal/policy"
)

var validRoles = map[string]bool{"member": true, "commander": true, "soc": true, "auditor": true, "admin": true, "release_officer": true}

type NewUser struct {
	ServiceNumber string   `json:"service_number"`
	FullName      string   `json:"full_name"`
	Rank          string   `json:"rank"`
	Unit          string   `json:"unit"`
	Clearance     int      `json:"clearance"`
	Compartments  []string `json:"compartments"`
	Roles         []string `json:"roles"`
}

func (n *NewUser) validate() error {
	n.ServiceNumber = strings.TrimSpace(n.ServiceNumber)
	if n.ServiceNumber == "" || n.FullName == "" || n.Rank == "" || n.Unit == "" {
		return httpx.E(400, "bad_request", "service_number, full_name, rank and unit are required")
	}
	if n.Clearance < 0 || n.Clearance > 4 {
		return httpx.E(400, "bad_request", "clearance must be 0..4")
	}
	if len(n.Roles) == 0 {
		n.Roles = []string{"member"}
	}
	for _, r := range n.Roles {
		if !validRoles[r] {
			return httpx.E(400, "bad_request", "unknown role "+r)
		}
	}
	if n.Compartments == nil {
		n.Compartments = []string{}
	}
	return nil
}

// CreateUser provisions a pending account and returns its one-time
// enrolment code (valid 72 h). Used by the admin API and siepmuctl.
func (s *Service) CreateUser(ctx context.Context, actor string, n NewUser) (*User, string, error) {
	if err := n.validate(); err != nil {
		return nil, "", err
	}
	code, hash := NewEnrollmentCode()
	handle := make([]byte, 64)
	copy(handle, uuid.New().NodeID())
	if _, err := randRead(handle); err != nil {
		return nil, "", err
	}
	id := uuid.New()
	_, err := s.db.Exec(ctx, `INSERT INTO users(id, service_number, full_name, rank, unit_code, clearance, compartments, roles, status, enroll_code_hash, enroll_expires_at, webauthn_handle)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'pending',$9,$10,$11)`,
		id, n.ServiceNumber, n.FullName, n.Rank, n.Unit, n.Clearance, n.Compartments, n.Roles, hash, time.Now().Add(72*time.Hour), handle)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate") {
			return nil, "", httpx.E(409, "conflict", "service number already exists")
		}
		if strings.Contains(err.Error(), "foreign key") {
			return nil, "", httpx.E(400, "bad_request", "unknown unit "+n.Unit)
		}
		return nil, "", err
	}
	s.audit.Record(ctx, audit.Entry{Actor: actor, Action: "admin.user.create", Resource: id.String(), Outcome: "success",
		Details: map[string]any{"service_number": n.ServiceNumber, "clearance": n.Clearance, "roles": n.Roles, "unit": n.Unit}})
	u, err := s.UserByID(ctx, id)
	return u, code, err
}

func (s *Service) EnsureUnit(ctx context.Context, code, name, parent string) error {
	var p *string
	if parent != "" {
		p = &parent
	}
	_, err := s.db.Exec(ctx, `INSERT INTO units(code, name, parent_code) VALUES ($1,$2,$3) ON CONFLICT (code) DO UPDATE SET name=EXCLUDED.name`, code, name, p)
	return err
}

func (s *Service) notifyRole(r *http.Request, role, kind, body, ref string) {
	s.NotifyRole(r.Context(), role, "", kind, body, ref)
}

// NotifyRole writes an in-app notification to every active user holding a
// role (optionally restricted to a unit) and pushes it to connected clients.
func (s *Service) NotifyRole(ctx context.Context, role, unit, kind, body, ref string) {
	rows, err := s.db.Query(ctx, `SELECT id FROM users WHERE $1 = ANY(roles) AND status='active' AND ($2 = '' OR unit_code=$2)`, role, unit)
	if err != nil {
		return
	}
	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	for _, id := range ids {
		s.Notify(ctx, id, kind, body, ref)
	}
}

func (s *Service) Notify(ctx context.Context, user uuid.UUID, kind, body, ref string) {
	var nid int64
	if err := s.db.QueryRow(ctx, `INSERT INTO notifications(user_id, kind, body, ref_id) VALUES ($1,$2,$3,$4) RETURNING id`, user, kind, body, ref).Scan(&nid); err == nil {
		s.bus.Notify(user.String(), map[string]any{"type": "notification", "id": nid, "kind": kind, "body": body, "ref": ref})
	}
}

// --------------------------------------------------------------- handlers

func (s *Service) handleMe(w http.ResponseWriter, r *http.Request) {
	p := FromContext(r.Context())
	var unitName string
	s.db.QueryRow(r.Context(), `SELECT name FROM units WHERE code=$1`, p.User.Unit).Scan(&unitName)
	httpx.JSON(w, 200, map[string]any{
		"user":      p.User,
		"unit_name": unitName,
		"device":    p.Device,
		"session": map[string]any{
			"id": p.Session.ID, "method": p.Session.AuthMethod, "mfa_strength": p.Session.MFAStrength,
			"created_at": p.Session.CreatedAt, "expires_at": p.Session.ExpiresAt, "breakglass": p.Breakglass,
		},
		"posture": map[string]any{"hardware_bound": p.HardwareBound, "patched": p.Patched, "geofence": p.Geofence, "risk": p.Risk},
	})
}

func (s *Service) handleMyNotifications(w http.ResponseWriter, r *http.Request) {
	p := FromContext(r.Context())
	rows, err := s.db.Query(r.Context(), `SELECT id, kind, body, coalesce(ref_id,''), created_at, read_at FROM notifications WHERE user_id=$1 ORDER BY id DESC LIMIT 100`, p.User.ID)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id int64
		var kind, body, ref string
		var ts time.Time
		var read *time.Time
		if err := rows.Scan(&id, &kind, &body, &ref, &ts, &read); err != nil {
			httpx.Fail(w, err)
			return
		}
		out = append(out, map[string]any{"id": id, "kind": kind, "body": body, "ref": ref, "created_at": ts, "read": read != nil})
	}
	httpx.JSON(w, 200, out)
}

func (s *Service) handleReadNotifications(w http.ResponseWriter, r *http.Request) {
	p := FromContext(r.Context())
	s.db.Exec(r.Context(), `UPDATE notifications SET read_at=now() WHERE user_id=$1 AND read_at IS NULL`, p.User.ID)
	w.WriteHeader(204)
}

func (s *Service) handleDirectory(w http.ResponseWriter, r *http.Request) {
	if err := s.Authorize(r, policy.Resource{Type: "directory"}, "read"); err != nil {
		httpx.Fail(w, err)
		return
	}
	q := "%" + strings.TrimSpace(r.URL.Query().Get("q")) + "%"
	rows, err := s.db.Query(r.Context(), `SELECT id, service_number, full_name, rank, unit_code, clearance, compartments FROM users WHERE status='active' AND (full_name ILIKE $1 OR service_number ILIKE $1 OR unit_code ILIKE $1) ORDER BY unit_code, full_name LIMIT 200`, q)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id uuid.UUID
		var sn, name, rank, unit string
		var cl int
		var comp []string
		if err := rows.Scan(&id, &sn, &name, &rank, &unit, &cl, &comp); err != nil {
			httpx.Fail(w, err)
			return
		}
		out = append(out, map[string]any{"id": id, "service_number": sn, "full_name": name, "rank": rank, "unit": unit, "clearance": cl, "compartments": comp})
	}
	httpx.JSON(w, 200, out)
}

func (s *Service) handleListUsers(w http.ResponseWriter, r *http.Request) {
	if err := s.Authorize(r, policy.Resource{Type: "admin"}, "read"); err != nil {
		httpx.Fail(w, err)
		return
	}
	rows, err := s.db.Query(r.Context(), `SELECT `+userCols+` FROM users ORDER BY unit_code, service_number`)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	defer rows.Close()
	out := []*User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			httpx.Fail(w, err)
			return
		}
		out = append(out, u)
	}
	httpx.JSON(w, 200, out)
}

func (s *Service) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	if err := s.Authorize(r, policy.Resource{Type: "admin"}, "manage"); err != nil {
		httpx.Fail(w, err)
		return
	}
	var n NewUser
	if err := httpx.Decode(r, 8192, &n); err != nil {
		httpx.Fail(w, err)
		return
	}
	p := FromContext(r.Context())
	u, code, err := s.CreateUser(r.Context(), p.User.ID.String(), n)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	httpx.JSON(w, 201, map[string]any{"user": u, "enroll_code": code, "enroll_expires_in_hours": 72})
}

func (s *Service) handleReissueCode(w http.ResponseWriter, r *http.Request) {
	if err := s.Authorize(r, policy.Resource{Type: "admin"}, "manage"); err != nil {
		httpx.Fail(w, err)
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Fail(w, httpx.E(400, "bad_request", "bad id"))
		return
	}
	code, hash := NewEnrollmentCode()
	tag, err := s.db.Exec(r.Context(), `UPDATE users SET enroll_code_hash=$2, enroll_expires_at=$3 WHERE id=$1`, id, hash, time.Now().Add(72*time.Hour))
	if err != nil || tag.RowsAffected() == 0 {
		httpx.Fail(w, httpx.E(404, "not_found", "user not found"))
		return
	}
	p := FromContext(r.Context())
	s.audit.Record(r.Context(), audit.Entry{Actor: p.User.ID.String(), Action: "admin.user.enroll_code", Resource: id.String(), Outcome: "success", IP: p.IP})
	httpx.JSON(w, 200, map[string]any{"enroll_code": code})
}

func (s *Service) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	if err := s.Authorize(r, policy.Resource{Type: "admin"}, "manage"); err != nil {
		httpx.Fail(w, err)
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Fail(w, httpx.E(400, "bad_request", "bad id"))
		return
	}
	var req struct {
		Clearance    *int      `json:"clearance"`
		Compartments *[]string `json:"compartments"`
		Roles        *[]string `json:"roles"`
		Status       *string   `json:"status"`
		Reason       string    `json:"reason"`
	}
	if err := httpx.Decode(r, 8192, &req); err != nil {
		httpx.Fail(w, err)
		return
	}
	p := FromContext(r.Context())
	if id == p.User.ID && (req.Roles != nil || req.Status != nil || req.Clearance != nil) {
		httpx.Fail(w, httpx.E(403, "forbidden", "administrators cannot change their own privileges"))
		return
	}
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	defer tx.Rollback(r.Context())
	changes := map[string]any{}
	if req.Clearance != nil {
		if *req.Clearance < 0 || *req.Clearance > 4 {
			httpx.Fail(w, httpx.E(400, "bad_request", "clearance must be 0..4"))
			return
		}
		tx.Exec(r.Context(), `UPDATE users SET clearance=$2 WHERE id=$1`, id, *req.Clearance)
		changes["clearance"] = *req.Clearance
	}
	if req.Compartments != nil {
		tx.Exec(r.Context(), `UPDATE users SET compartments=$2 WHERE id=$1`, id, *req.Compartments)
		changes["compartments"] = *req.Compartments
	}
	if req.Roles != nil {
		for _, ro := range *req.Roles {
			if !validRoles[ro] {
				httpx.Fail(w, httpx.E(400, "bad_request", "unknown role "+ro))
				return
			}
		}
		tx.Exec(r.Context(), `UPDATE users SET roles=$2 WHERE id=$1`, id, *req.Roles)
		changes["roles"] = *req.Roles
	}
	if req.Status != nil {
		if *req.Status != "active" && *req.Status != "suspended" {
			httpx.Fail(w, httpx.E(400, "bad_request", "status must be active or suspended"))
			return
		}
		tx.Exec(r.Context(), `UPDATE users SET status=$2, suspended_reason=$3 WHERE id=$1`, id, *req.Status, req.Reason)
		if *req.Status == "suspended" {
			tx.Exec(r.Context(), `UPDATE sessions SET revoked_at=now(), revoked_reason='account suspended' WHERE user_id=$1 AND revoked_at IS NULL`, id)
		}
		changes["status"] = *req.Status
	}
	if err := tx.Commit(r.Context()); err != nil {
		httpx.Fail(w, err)
		return
	}
	s.audit.Record(r.Context(), audit.Entry{Actor: p.User.ID.String(), Action: "admin.user.update", Resource: id.String(), Outcome: "success", IP: p.IP, Details: changes})
	if _, ok := changes["roles"]; ok {
		s.secEvent(r.Context(), "identity.privilege_change", 2, id.String(), p.IP, []string{"T1098"}, "roles changed by "+p.User.ServiceNumber, changes)
	}
	u, _ := s.UserByID(r.Context(), id)
	httpx.JSON(w, 200, u)
}

func (s *Service) handleListDevices(w http.ResponseWriter, r *http.Request) {
	if err := s.Authorize(r, policy.Resource{Type: "admin"}, "read"); err != nil {
		httpx.Fail(w, err)
		return
	}
	st := r.URL.Query().Get("status")
	rows, err := s.db.Query(r.Context(), `SELECT d.id, d.user_id, d.jkt, d.label, d.user_agent, d.managed, d.status, coalesce(d.cert_serial,''), d.created_at, d.last_seen_at, u.service_number, u.rank || ' ' || u.full_name
		FROM devices d JOIN users u ON u.id=d.user_id WHERE ($1='' OR d.status=$1) ORDER BY d.created_at DESC LIMIT 500`, st)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		d := &Device{}
		var sn, name string
		if err := rows.Scan(&d.ID, &d.UserID, &d.JKT, &d.Label, &d.UserAgent, &d.Managed, &d.Status, &d.CertSerial, &d.CreatedAt, &d.LastSeen, &sn, &name); err != nil {
			httpx.Fail(w, err)
			return
		}
		out = append(out, map[string]any{"device": d, "service_number": sn, "user_name": name})
	}
	httpx.JSON(w, 200, out)
}

func (s *Service) handleDeviceAction(w http.ResponseWriter, r *http.Request) {
	if err := s.Authorize(r, policy.Resource{Type: "admin"}, "manage"); err != nil {
		httpx.Fail(w, err)
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Fail(w, httpx.E(400, "bad_request", "bad id"))
		return
	}
	action := r.PathValue("action")
	p := FromContext(r.Context())
	ctx := r.Context()
	tx, err := s.db.Begin(ctx)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	defer tx.Rollback(ctx)
	d, err := scanDevice(tx.QueryRow(ctx, `SELECT `+deviceCols+` FROM devices WHERE id=$1 FOR UPDATE`, id))
	if err != nil {
		httpx.Fail(w, httpx.E(404, "not_found", "device not found"))
		return
	}
	switch action {
	case "approve":
		if d.Status != "pending" {
			httpx.Fail(w, httpx.E(409, "conflict", "device is not pending"))
			return
		}
		var jwkRaw []byte
		tx.QueryRow(ctx, `SELECT public_jwk FROM devices WHERE id=$1`, id).Scan(&jwkRaw)
		var jwk map[string]any
		json.Unmarshal(jwkRaw, &jwk)
		u, err := s.UserByID(ctx, d.UserID)
		if err != nil {
			httpx.Fail(w, err)
			return
		}
		if err := s.issueDeviceCert(r, tx, d, u, jwk); err != nil {
			httpx.Fail(w, err)
			return
		}
		tx.Exec(ctx, `UPDATE devices SET status='active', managed=true, approved_by=$2 WHERE id=$1`, id, p.User.ID)
	case "revoke":
		tx.Exec(ctx, `UPDATE devices SET status='revoked' WHERE id=$1`, id)
		tx.Exec(ctx, `UPDATE sessions SET revoked_at=now(), revoked_reason='device revoked' WHERE device_id=$1 AND revoked_at IS NULL`, id)
	default:
		httpx.Fail(w, httpx.E(404, "not_found", "unknown action"))
		return
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.Fail(w, err)
		return
	}
	s.audit.Record(ctx, audit.Entry{Actor: p.User.ID.String(), Action: "admin.device." + action, Resource: id.String(), Outcome: "success", IP: p.IP})
	s.Notify(ctx, d.UserID, "device_"+action, "Your device "+d.Label+" was "+action+"d by "+p.User.Rank+" "+p.User.FullName, id.String())
	w.WriteHeader(204)
}

func (s *Service) handleUnits(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query(r.Context(), `SELECT code, name, coalesce(parent_code,'') FROM units ORDER BY code`)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	defer rows.Close()
	out := []map[string]string{}
	for rows.Next() {
		var c, n, p string
		rows.Scan(&c, &n, &p)
		out = append(out, map[string]string{"code": c, "name": n, "parent": p})
	}
	httpx.JSON(w, 200, out)
}

func (s *Service) handleCreateUnit(w http.ResponseWriter, r *http.Request) {
	if err := s.Authorize(r, policy.Resource{Type: "admin"}, "manage"); err != nil {
		httpx.Fail(w, err)
		return
	}
	var req struct {
		Code, Name, Parent string
	}
	if err := httpx.Decode(r, 4096, &req); err != nil {
		httpx.Fail(w, err)
		return
	}
	if req.Code == "" || req.Name == "" {
		httpx.Fail(w, httpx.E(400, "bad_request", "code and name required"))
		return
	}
	if err := s.EnsureUnit(r.Context(), req.Code, req.Name, req.Parent); err != nil {
		httpx.Fail(w, httpx.E(400, "bad_request", err.Error()))
		return
	}
	p := FromContext(r.Context())
	s.audit.Record(r.Context(), audit.Entry{Actor: p.User.ID.String(), Action: "admin.unit.upsert", Resource: req.Code, Outcome: "success", IP: p.IP})
	w.WriteHeader(204)
}
