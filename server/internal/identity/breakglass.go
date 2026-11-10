package identity

import (
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Neurvinch/SIEPMU/server/internal/audit"
	"github.com/Neurvinch/SIEPMU/server/internal/httpx"
	"github.com/Neurvinch/SIEPMU/server/internal/policy"
)

// Break-glass: emergency elevation needs a quorum (default two) of distinct
// commanders/admins, none of whom may be the requester; it is time-boxed and
// every activation is queued for mandatory auditor post-review.

func (s *Service) handleBreakglassCreate(w http.ResponseWriter, r *http.Request) {
	if err := s.Authorize(r, policy.Resource{Type: "breakglass"}, "create"); err != nil {
		httpx.Fail(w, err)
		return
	}
	var req struct {
		Reason       string   `json:"reason"`
		Clearance    int      `json:"clearance"`
		Compartments []string `json:"compartments"`
	}
	if err := httpx.Decode(r, 8192, &req); err != nil {
		httpx.Fail(w, err)
		return
	}
	if len(strings.TrimSpace(req.Reason)) < 20 {
		httpx.Fail(w, httpx.E(400, "bad_request", "state the operational reason (at least 20 characters)"))
		return
	}
	if req.Clearance < 0 || req.Clearance > 4 {
		httpx.Fail(w, httpx.E(400, "bad_request", "clearance must be 0..4"))
		return
	}
	if req.Compartments == nil {
		req.Compartments = []string{}
	}
	p := FromContext(r.Context())
	id := uuid.New()
	if _, err := s.db.Exec(r.Context(), `INSERT INTO breakglass_requests(id, requester_id, reason, grant_clearance, grant_compartments) VALUES ($1,$2,$3,$4,$5)`,
		id, p.User.ID, req.Reason, req.Clearance, req.Compartments); err != nil {
		httpx.Fail(w, err)
		return
	}
	s.audit.Record(r.Context(), audit.Entry{Actor: p.User.ID.String(), Action: "breakglass.request", Resource: id.String(), Outcome: "success", IP: p.IP,
		Details: map[string]any{"reason": req.Reason, "clearance": req.Clearance, "compartments": req.Compartments}})
	s.secEvent(r.Context(), "breakglass.requested", 2, p.User.ID.String(), p.IP, []string{"T1078"}, "break-glass elevation requested", map[string]any{"request_id": id.String()})
	msg := p.User.Rank + " " + p.User.FullName + " requests break-glass access to " + Levels[req.Clearance] + ": " + req.Reason
	s.NotifyRole(r.Context(), "commander", "", "breakglass_pending", msg, id.String())
	s.NotifyRole(r.Context(), "admin", "", "breakglass_pending", msg, id.String())
	httpx.JSON(w, 201, map[string]any{"id": id, "quorum": s.cfg.BreakglassQuorum})
}

type bgRow struct {
	ID           uuid.UUID   `json:"id"`
	RequesterID  uuid.UUID   `json:"requester_id"`
	Requester    string      `json:"requester"`
	Reason       string      `json:"reason"`
	Clearance    int         `json:"clearance"`
	Compartments []string    `json:"compartments"`
	Approvals    []uuid.UUID `json:"approvals"`
	Status       string      `json:"status"`
	CreatedAt    time.Time   `json:"created_at"`
	ExpiresAt    *time.Time  `json:"expires_at"`
	ReviewNote   *string     `json:"review_note"`
}

func (s *Service) handleBreakglassList(w http.ResponseWriter, r *http.Request) {
	p := FromContext(r.Context())
	// Expire elapsed grants so state is accurate for reviewers.
	s.db.Exec(r.Context(), `UPDATE breakglass_requests SET status='expired' WHERE status='active' AND expires_at < now()`)
	rows, err := s.db.Query(r.Context(), `SELECT b.id, b.requester_id, u.rank||' '||u.full_name, b.reason, b.grant_clearance, b.grant_compartments, b.approvals, b.status, b.created_at, b.expires_at, b.review_note
		FROM breakglass_requests b JOIN users u ON u.id=b.requester_id
		WHERE b.requester_id=$1 OR $2 ORDER BY b.created_at DESC LIMIT 200`, p.User.ID,
		p.User.HasRole("commander") || p.User.HasRole("admin") || p.User.HasRole("auditor"))
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	defer rows.Close()
	out := []bgRow{}
	for rows.Next() {
		var b bgRow
		if err := rows.Scan(&b.ID, &b.RequesterID, &b.Requester, &b.Reason, &b.Clearance, &b.Compartments, &b.Approvals, &b.Status, &b.CreatedAt, &b.ExpiresAt, &b.ReviewNote); err != nil {
			httpx.Fail(w, err)
			return
		}
		out = append(out, b)
	}
	httpx.JSON(w, 200, out)
}

func (s *Service) handleBreakglassApprove(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Fail(w, httpx.E(400, "bad_request", "bad id"))
		return
	}
	ctx := r.Context()
	p := FromContext(ctx)
	tx, err := s.db.Begin(ctx)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	defer tx.Rollback(ctx)
	var requester uuid.UUID
	var approvals []uuid.UUID
	var status string
	if err := tx.QueryRow(ctx, `SELECT requester_id, approvals, status FROM breakglass_requests WHERE id=$1 FOR UPDATE`, id).Scan(&requester, &approvals, &status); err != nil {
		httpx.Fail(w, httpx.E(404, "not_found", "request not found"))
		return
	}
	if err := s.Authorize(r, policy.Resource{Type: "breakglass", ID: id.String(), Originator: requester.String()}, "approve"); err != nil {
		httpx.Fail(w, err)
		return
	}
	if status != "pending" {
		httpx.Fail(w, httpx.E(409, "conflict", "request is "+status))
		return
	}
	for _, a := range approvals {
		if a == p.User.ID {
			httpx.Fail(w, httpx.E(409, "conflict", "you have already approved this request"))
			return
		}
	}
	approvals = append(approvals, p.User.ID)
	activated := len(approvals) >= s.cfg.BreakglassQuorum
	if activated {
		exp := time.Now().Add(s.cfg.BreakglassTTL)
		tx.Exec(ctx, `UPDATE breakglass_requests SET approvals=$2, status='active', activated_at=now(), expires_at=$3 WHERE id=$1`, id, approvals, exp)
		tx.Exec(ctx, `UPDATE sessions SET breakglass_id=$2 WHERE user_id=$1 AND revoked_at IS NULL AND expires_at > now()`, requester, id)
	} else {
		tx.Exec(ctx, `UPDATE breakglass_requests SET approvals=$2 WHERE id=$1`, id, approvals)
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.Fail(w, err)
		return
	}
	s.audit.Record(ctx, audit.Entry{Actor: p.User.ID.String(), Action: "breakglass.approve", Resource: id.String(), Outcome: "success", IP: p.IP, Details: map[string]any{"approvals": len(approvals), "activated": activated}})
	if activated {
		s.secEvent(ctx, "breakglass.activated", 3, requester.String(), p.IP, []string{"T1078"}, "break-glass elevation activated after four-eyes approval", map[string]any{"request_id": id.String()})
		s.Notify(ctx, requester, "breakglass_active", "Break-glass access granted for "+s.cfg.BreakglassTTL.String()+". All actions are recorded for post-review.", id.String())
		s.NotifyRole(ctx, "auditor", "", "breakglass_review", "Break-glass activation requires post-review", id.String())
	}
	httpx.JSON(w, 200, map[string]any{"approvals": len(approvals), "activated": activated})
}

func (s *Service) handleBreakglassReview(w http.ResponseWriter, r *http.Request) {
	if err := s.Authorize(r, policy.Resource{Type: "breakglass"}, "review"); err != nil {
		httpx.Fail(w, err)
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Fail(w, httpx.E(400, "bad_request", "bad id"))
		return
	}
	var req struct {
		Note string `json:"note"`
	}
	if err := httpx.Decode(r, 8192, &req); err != nil || strings.TrimSpace(req.Note) == "" {
		httpx.Fail(w, httpx.E(400, "bad_request", "a review note is required"))
		return
	}
	p := FromContext(r.Context())
	tag, err := s.db.Exec(r.Context(), `UPDATE breakglass_requests SET status='reviewed', review_note=$2, reviewed_by=$3 WHERE id=$1 AND status IN ('active','expired')`, id, req.Note, p.User.ID)
	if err != nil || tag.RowsAffected() == 0 {
		httpx.Fail(w, httpx.E(409, "conflict", "only activated grants can be reviewed"))
		return
	}
	s.db.Exec(r.Context(), `UPDATE sessions SET breakglass_id=NULL WHERE breakglass_id=$1`, id)
	s.audit.Record(r.Context(), audit.Entry{Actor: p.User.ID.String(), Action: "breakglass.review", Resource: id.String(), Outcome: "success", IP: p.IP, Details: map[string]any{"note": req.Note}})
	w.WriteHeader(204)
}

// Routes registers the identity endpoints. pub are unauthenticated (rate
// limited by the gateway); auth wraps handlers that need a principal.
func (s *Service) Routes(mux *http.ServeMux, auth func(http.HandlerFunc) http.Handler) {
	mux.HandleFunc("POST /api/auth/enroll/begin", s.handleEnrollBegin)
	mux.HandleFunc("POST /api/auth/enroll/finish", s.handleEnrollFinish)
	mux.HandleFunc("POST /api/auth/login/begin", s.handleLoginBegin)
	mux.HandleFunc("POST /api/auth/login/finish", s.handleLoginFinish)
	mux.HandleFunc("POST /api/auth/refresh", s.handleRefresh)
	mux.Handle("POST /api/auth/logout", auth(s.handleLogout))
	mux.Handle("GET /api/me", auth(s.handleMe))
	mux.Handle("GET /api/me/notifications", auth(s.handleMyNotifications))
	mux.Handle("POST /api/me/notifications/read", auth(s.handleReadNotifications))
	mux.Handle("GET /api/directory", auth(s.handleDirectory))
	mux.Handle("GET /api/units", auth(s.handleUnits))
	mux.Handle("POST /api/admin/units", auth(s.handleCreateUnit))
	mux.Handle("GET /api/admin/users", auth(s.handleListUsers))
	mux.Handle("POST /api/admin/users", auth(s.handleCreateUser))
	mux.Handle("PATCH /api/admin/users/{id}", auth(s.handleUpdateUser))
	mux.Handle("POST /api/admin/users/{id}/enroll-code", auth(s.handleReissueCode))
	mux.Handle("GET /api/admin/devices", auth(s.handleListDevices))
	mux.Handle("POST /api/admin/devices/{id}/{action}", auth(s.handleDeviceAction))
	mux.Handle("POST /api/breakglass", auth(s.handleBreakglassCreate))
	mux.Handle("GET /api/breakglass", auth(s.handleBreakglassList))
	mux.Handle("POST /api/breakglass/{id}/approve", auth(s.handleBreakglassApprove))
	mux.Handle("POST /api/breakglass/{id}/review", auth(s.handleBreakglassReview))
}
