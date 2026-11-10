package guard

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Neurvinch/SIEPMU/server/internal/audit"
	"github.com/Neurvinch/SIEPMU/server/internal/config"
	"github.com/Neurvinch/SIEPMU/server/internal/cryptoprov"
	"github.com/Neurvinch/SIEPMU/server/internal/events"
	"github.com/Neurvinch/SIEPMU/server/internal/httpx"
	"github.com/Neurvinch/SIEPMU/server/internal/identity"
	"github.com/Neurvinch/SIEPMU/server/internal/policy"
	"github.com/Neurvinch/SIEPMU/server/internal/store"
)

// KEK is the HSM key that protects content held for release.
const KEK = "kek-guard-hold"

type Service struct {
	cfg    *config.Config
	db     *store.Store
	id     *identity.Service
	kms    cryptoprov.KMS
	p      cryptoprov.Provider
	signer cryptoprov.Signer
	audit  *audit.Log
	bus    *events.Bus
}

func New(cfg *config.Config, db *store.Store, id *identity.Service, kms cryptoprov.KMS, p cryptoprov.Provider, signer cryptoprov.Signer, al *audit.Log, bus *events.Bus) *Service {
	return &Service{cfg: cfg, db: db, id: id, kms: kms, p: p, signer: signer, audit: al, bus: bus}
}

// handleSubmit takes the content as the raw request body; metadata is in
// query parameters so the body can be hashed and filtered as-is.
func (s *Service) handleSubmit(w http.ResponseWriter, r *http.Request) {
	if err := s.id.Authorize(r, policy.Resource{Type: "guard"}, "create"); err != nil {
		httpx.Fail(w, err)
		return
	}
	q := r.URL.Query()
	filename := q.Get("filename")
	class, err := strconv.Atoi(q.Get("classification"))
	just := strings.TrimSpace(q.Get("justification"))
	if err != nil || class < 0 || class > 4 || len(just) < 10 {
		httpx.Fail(w, httpx.E(400, "bad_request", "filename, classification (0..4) and a justification of at least 10 characters are required"))
		return
	}
	p := identity.FromContext(r.Context())
	if class > p.User.Clearance {
		httpx.Fail(w, httpx.E(403, "forbidden", "cannot submit content above your own clearance"))
		return
	}
	content, err := io.ReadAll(io.LimitReader(r.Body, s.cfg.Guard.MaxSize+1))
	if err != nil {
		httpx.Fail(w, httpx.E(400, "bad_request", err.Error()))
		return
	}
	rep := Inspect(FilterConfig{MaxSize: s.cfg.Guard.MaxSize, AllowedTypes: s.cfg.Guard.AllowedTypes, DirtyWords: s.cfg.Guard.DirtyWords}, filename, q.Get("content_type"), content)
	dek := make([]byte, 32)
	rand.Read(dek)
	id := uuid.New()
	sealed, err := s.p.AEAD().Seal(dek, content, id[:])
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	wrapped, err := s.kms.Wrap(KEK, dek, id[:])
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	status := "pending"
	if rep.Blocked {
		status = "blocked"
	}
	ctx := r.Context()
	if _, err := s.db.Exec(ctx, `INSERT INTO guard_releases(id, direction, filename, classification, content_type, size, sha384, sealed_body, wrapped_dek, kek_id, justification, submitted_by, filter_report, status)
		VALUES ($1,'black_to_red',$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`, id, filename, class, rep.DetectedType, len(content), s.p.Hash384(content), sealed, wrapped, KEK, just, p.User.ID, rep, status); err != nil {
		httpx.Fail(w, err)
		return
	}
	s.audit.Record(ctx, audit.Entry{Actor: p.User.ID.String(), Action: "guard.submit", Resource: id.String(), Outcome: map[bool]string{true: "blocked", false: "success"}[rep.Blocked], IP: p.IP,
		Details: map[string]any{"filename": filename, "classification": class, "size": len(content), "sha384": base64.StdEncoding.EncodeToString(s.p.Hash384(content)), "filter": rep.Findings}})
	if rep.Blocked {
		s.bus.PublishSec(ctx, events.SecEvent{Source: "guard", Kind: "guard.filter_block", Severity: 3, UserID: p.User.ID.String(), IP: p.IP, AttackIDs: []string{"T1048"},
			Summary: "cross-domain release blocked by content filter: " + filename, Data: map[string]any{"release": id.String(), "findings": rep.Findings}})
	} else {
		s.id.NotifyRole(ctx, "release_officer", "", "guard_pending", p.User.Rank+" "+p.User.FullName+" requests cross-domain release of "+filename, id.String())
	}
	httpx.JSON(w, 201, map[string]any{"id": id, "status": status, "filter_report": rep})
}

func (s *Service) handleList(w http.ResponseWriter, r *http.Request) {
	p := identity.FromContext(r.Context())
	all := p.User.HasRole("release_officer") || p.User.HasRole("auditor")
	rows, err := s.db.Query(r.Context(), `SELECT g.id, g.filename, g.classification, g.content_type, g.size, g.sha384, g.justification, g.submitted_by, u.rank||' '||u.full_name, g.approvals, g.filter_report, g.status, g.created_at, g.transferred_at
		FROM guard_releases g JOIN users u ON u.id=g.submitted_by WHERE $2 OR g.submitted_by=$1 ORDER BY g.created_at DESC LIMIT 200`, p.User.ID, all)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, sub uuid.UUID
		var fn, ct, just, subName, status string
		var class int
		var size int64
		var sha []byte
		var approvals []uuid.UUID
		var rep Report
		var created time.Time
		var transferred *time.Time
		if err := rows.Scan(&id, &fn, &class, &ct, &size, &sha, &just, &sub, &subName, &approvals, &rep, &status, &created, &transferred); err != nil {
			httpx.Fail(w, err)
			return
		}
		out = append(out, map[string]any{"id": id, "filename": fn, "classification": class, "content_type": ct, "size": size, "sha384": sha, "justification": just,
			"submitted_by": sub, "submitter": subName, "approvals": approvals, "filter_report": rep, "status": status, "created_at": created, "transferred_at": transferred, "quorum": s.cfg.Guard.Quorum})
	}
	httpx.JSON(w, 200, out)
}

func (s *Service) content(r *http.Request, id uuid.UUID) ([]byte, error) {
	var sealed, wrapped []byte
	var kek string
	if err := s.db.QueryRow(r.Context(), `SELECT sealed_body, wrapped_dek, kek_id FROM guard_releases WHERE id=$1`, id).Scan(&sealed, &wrapped, &kek); err != nil {
		return nil, httpx.E(404, "not_found", "release not found")
	}
	dek, err := s.kms.Unwrap(kek, wrapped, id[:])
	if err != nil {
		return nil, err
	}
	return s.p.AEAD().Open(dek, sealed, id[:])
}

// handleContent lets a release officer inspect what they are asked to release.
func (s *Service) handleContent(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Fail(w, httpx.E(400, "bad_request", "bad id"))
		return
	}
	var class int
	var sub uuid.UUID
	if err := s.db.QueryRow(r.Context(), `SELECT classification, submitted_by FROM guard_releases WHERE id=$1`, id).Scan(&class, &sub); err != nil {
		httpx.Fail(w, httpx.E(404, "not_found", "release not found"))
		return
	}
	if err := s.id.Authorize(r, policy.Resource{Type: "guard", ID: id.String(), Classification: class, Originator: sub.String()}, "read"); err != nil {
		httpx.Fail(w, err)
		return
	}
	c, err := s.content(r, id)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	p := identity.FromContext(r.Context())
	s.audit.Record(r.Context(), audit.Entry{Actor: p.User.ID.String(), Action: "guard.inspect", Resource: id.String(), Outcome: "success", IP: p.IP})
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(c)
}

func (s *Service) handleDecision(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Fail(w, httpx.E(400, "bad_request", "bad id"))
		return
	}
	decision := r.PathValue("decision")
	ctx := r.Context()
	p := identity.FromContext(ctx)
	tx, err := s.db.Begin(ctx)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	defer tx.Rollback(ctx)
	var meta Meta
	var sub uuid.UUID
	var approvals []uuid.UUID
	var status string
	if err := tx.QueryRow(ctx, `SELECT filename, content_type, classification, size, sha384, submitted_by, approvals, status FROM guard_releases WHERE id=$1 FOR UPDATE`, id).
		Scan(&meta.Filename, &meta.ContentType, &meta.Classification, &meta.Size, &meta.SHA384, &sub, &approvals, &status); err != nil {
		httpx.Fail(w, httpx.E(404, "not_found", "release not found"))
		return
	}
	if err := s.id.Authorize(r, policy.Resource{Type: "guard", ID: id.String(), Classification: meta.Classification, Originator: sub.String()}, "approve"); err != nil {
		httpx.Fail(w, err)
		return
	}
	if status != "pending" {
		httpx.Fail(w, httpx.E(409, "conflict", "release is "+status))
		return
	}
	if decision == "reject" {
		tx.Exec(ctx, `UPDATE guard_releases SET status='rejected', rejected_by=$2 WHERE id=$1`, id, p.User.ID)
		tx.Commit(ctx)
		s.audit.Record(ctx, audit.Entry{Actor: p.User.ID.String(), Action: "guard.reject", Resource: id.String(), Outcome: "success", IP: p.IP})
		s.id.Notify(ctx, sub, "guard_rejected", "Cross-domain release of "+meta.Filename+" was rejected", id.String())
		httpx.JSON(w, 200, map[string]any{"status": "rejected"})
		return
	}
	if decision != "approve" {
		httpx.Fail(w, httpx.E(404, "not_found", "unknown decision"))
		return
	}
	for _, a := range approvals {
		if a == p.User.ID {
			httpx.Fail(w, httpx.E(409, "conflict", "you have already approved this release"))
			return
		}
	}
	approvals = append(approvals, p.User.ID)
	if len(approvals) < s.cfg.Guard.Quorum {
		tx.Exec(ctx, `UPDATE guard_releases SET approvals=$2 WHERE id=$1`, id, approvals)
		tx.Commit(ctx)
		s.audit.Record(ctx, audit.Entry{Actor: p.User.ID.String(), Action: "guard.approve", Resource: id.String(), Outcome: "success", IP: p.IP, Details: map[string]any{"approvals": len(approvals)}})
		httpx.JSON(w, 200, map[string]any{"status": "pending", "approvals": len(approvals), "quorum": s.cfg.Guard.Quorum})
		return
	}
	// Quorum reached: seal for the RED receiver and push through the diode.
	kemPub, err := base64.StdEncoding.DecodeString(s.cfg.Guard.ReceiverKEMPub)
	if err != nil || len(kemPub) == 0 || s.cfg.Guard.DiodeAddr == "" {
		httpx.Fail(w, httpx.E(503, "guard_unconfigured", "guard.receiver_kem_pub and guard.diode_addr are not configured"))
		return
	}
	content, err := s.content(r, id)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	meta.ID = id.String()
	meta.SubmittedBy = sub.String()
	for _, a := range approvals {
		meta.ReleasedBy = append(meta.ReleasedBy, a.String())
	}
	meta.ReleasedAt = time.Now().UTC()
	bundle, err := Seal(s.p, s.signer, kemPub, meta, content)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	if err := Send(s.cfg.Guard.DiodeAddr, bundle, 3); err != nil {
		httpx.Fail(w, httpx.E(502, "diode_error", err.Error()))
		return
	}
	tx.Exec(ctx, `UPDATE guard_releases SET approvals=$2, status='transferred', transferred_at=now() WHERE id=$1`, id, approvals)
	if err := tx.Commit(ctx); err != nil {
		httpx.Fail(w, err)
		return
	}
	s.audit.Record(ctx, audit.Entry{Actor: p.User.ID.String(), Action: "guard.release", Resource: id.String(), Outcome: "success", IP: p.IP,
		Details: map[string]any{"released_by": meta.ReleasedBy, "sha384": base64.StdEncoding.EncodeToString(meta.SHA384), "bundle_bytes": len(bundle), "classification": meta.Classification}})
	s.bus.PublishSec(ctx, events.SecEvent{Source: "guard", Kind: "guard.released", Severity: 1, UserID: sub.String(), IP: p.IP, Summary: "cross-domain release transferred: " + meta.Filename, Data: map[string]any{"release": id.String()}})
	s.id.Notify(ctx, sub, "guard_released", "Cross-domain release of "+meta.Filename+" was transferred to the RED segment", id.String())
	httpx.JSON(w, 200, map[string]any{"status": "transferred", "approvals": len(approvals)})
}

func (s *Service) Routes(mux *http.ServeMux, auth func(http.HandlerFunc) http.Handler) {
	mux.Handle("POST /api/guard/releases", auth(s.handleSubmit))
	mux.Handle("GET /api/guard/releases", auth(s.handleList))
	mux.Handle("GET /api/guard/releases/{id}/content", auth(s.handleContent))
	mux.Handle("POST /api/guard/releases/{id}/{decision}", auth(s.handleDecision))
}
