// Package messaging is the delivery service for end-to-end encrypted
// traffic. It never sees plaintext: group channels carry RFC 9420 MLS
// messages (ciphersuite 0x0057, X-Wing + ML-DSA-87) and direct channels carry
// Double Ratchet envelopes. The server's jobs are authorisation (who may be
// in a channel at which classification), total ordering of MLS handshake
// messages per group (one commit per epoch), store-and-forward delivery and
// realtime fan-out.
package messaging

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Neurvinch/SIEPMU/server/internal/audit"
	"github.com/Neurvinch/SIEPMU/server/internal/events"
	"github.com/Neurvinch/SIEPMU/server/internal/httpx"
	"github.com/Neurvinch/SIEPMU/server/internal/identity"
	"github.com/Neurvinch/SIEPMU/server/internal/policy"
	"github.com/Neurvinch/SIEPMU/server/internal/store"
)

// MLSCipherSuite is MLS_256_XWING_AES256GCM_SHA512_MLDSA87.
const MLSCipherSuite = 87

type Service struct {
	db    *store.Store
	id    *identity.Service
	audit *audit.Log
	bus   *events.Bus
}

func New(db *store.Store, id *identity.Service, al *audit.Log, bus *events.Bus) *Service {
	return &Service{db: db, id: id, audit: al, bus: bus}
}

type Channel struct {
	ID             uuid.UUID `json:"id"`
	Name           string    `json:"name"`
	Kind           string    `json:"kind"`
	Classification int       `json:"classification"`
	Compartments   []string  `json:"compartments"`
	Unit           string    `json:"unit"`
	CreatedBy      uuid.UUID `json:"created_by"`
	Epoch          int64     `json:"epoch"`
	CreatedAt      time.Time `json:"created_at"`
	Role           string    `json:"role,omitempty"`
	Members        []Member  `json:"members,omitempty"`
}

type Member struct {
	UserID        uuid.UUID `json:"user_id"`
	ServiceNumber string    `json:"service_number"`
	Name          string    `json:"name"`
	Rank          string    `json:"rank"`
	Unit          string    `json:"unit"`
	Role          string    `json:"role"`
}

const chanCols = `c.id, c.name, c.kind, c.classification, c.compartments, c.unit_code, c.created_by, c.epoch, c.created_at`

func scanChannel(row pgx.Row, extra ...any) (*Channel, error) {
	c := &Channel{}
	dst := append([]any{&c.ID, &c.Name, &c.Kind, &c.Classification, &c.Compartments, &c.Unit, &c.CreatedBy, &c.Epoch, &c.CreatedAt}, extra...)
	return c, row.Scan(dst...)
}

// LoadChannel returns the channel and the caller's membership role ("" if none).
func (s *Service) LoadChannel(ctx context.Context, id, user uuid.UUID) (*Channel, string, error) {
	var role *string
	c, err := scanChannel(s.db.QueryRow(ctx, `SELECT `+chanCols+`, m.role FROM channels c LEFT JOIN channel_members m ON m.channel_id=c.id AND m.user_id=$2 WHERE c.id=$1`, id, user), &role)
	if err != nil {
		return nil, "", httpx.E(404, "not_found", "channel not found")
	}
	r := ""
	if role != nil {
		r = *role
	}
	return c, r, nil
}

// Resource converts a channel into the ABAC resource for the caller.
func (c *Channel) Resource(role string) policy.Resource {
	return policy.Resource{Type: "channel", ID: c.ID.String(), Classification: c.Classification, Compartments: c.Compartments,
		Unit: c.Unit, Originator: c.CreatedBy.String(), Member: role != "", Owner: role == "owner"}
}

// authorizeChannel loads the channel from the path and evaluates policy.
func (s *Service) authorizeChannel(r *http.Request, action string) (*Channel, string, error) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return nil, "", httpx.E(400, "bad_request", "bad channel id")
	}
	p := identity.FromContext(r.Context())
	c, role, err := s.LoadChannel(r.Context(), id, p.User.ID)
	if err != nil {
		return nil, "", err
	}
	if err := s.id.Authorize(r, c.Resource(role), action); err != nil {
		return nil, "", err
	}
	return c, role, nil
}

// eligible checks that a prospective member is cleared for the channel.
func (s *Service) eligible(ctx context.Context, c *Channel, uid uuid.UUID) (*identity.User, error) {
	u, err := s.id.UserByID(ctx, uid)
	if err != nil {
		return nil, httpx.E(404, "not_found", "user not found")
	}
	if u.Status != "active" {
		return nil, httpx.E(409, "ineligible", u.ServiceNumber+" is not active")
	}
	if u.Clearance < c.Classification {
		return nil, httpx.E(409, "ineligible", u.ServiceNumber+" lacks clearance for "+identity.Levels[c.Classification])
	}
	have := map[string]bool{}
	for _, x := range u.Compartments {
		have[x] = true
	}
	for _, x := range c.Compartments {
		if !have[x] {
			return nil, httpx.E(409, "ineligible", u.ServiceNumber+" is not read into compartment "+x)
		}
	}
	return u, nil
}

func (s *Service) handleCreateChannel(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name           string      `json:"name"`
		Kind           string      `json:"kind"`
		Classification int         `json:"classification"`
		Compartments   []string    `json:"compartments"`
		Members        []uuid.UUID `json:"members"`
	}
	if err := httpx.Decode(r, 16<<10, &req); err != nil {
		httpx.Fail(w, err)
		return
	}
	p := identity.FromContext(r.Context())
	if req.Compartments == nil {
		req.Compartments = []string{}
	}
	if req.Kind != "group" && req.Kind != "direct" {
		httpx.Fail(w, httpx.E(400, "bad_request", "kind must be group or direct"))
		return
	}
	if req.Classification < 0 || req.Classification > 4 {
		httpx.Fail(w, httpx.E(400, "bad_request", "classification must be 0..4"))
		return
	}
	others := []uuid.UUID{}
	seen := map[uuid.UUID]bool{p.User.ID: true}
	for _, m := range req.Members {
		if !seen[m] {
			seen[m] = true
			others = append(others, m)
		}
	}
	if req.Kind == "direct" && len(others) != 1 {
		httpx.Fail(w, httpx.E(400, "bad_request", "a direct channel has exactly one other member"))
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Kind == "group" && (req.Name == "" || len(req.Name) > 80) {
		httpx.Fail(w, httpx.E(400, "bad_request", "group name required (max 80 chars)"))
		return
	}
	c := &Channel{ID: uuid.New(), Name: req.Name, Kind: req.Kind, Classification: req.Classification, Compartments: req.Compartments, Unit: p.User.Unit, CreatedBy: p.User.ID}
	if err := s.id.Authorize(r, policy.Resource{Type: "channel", Classification: c.Classification, Compartments: c.Compartments, Unit: c.Unit}, "create"); err != nil {
		httpx.Fail(w, err)
		return
	}
	var users []*identity.User
	for _, m := range others {
		u, err := s.eligible(r.Context(), c, m)
		if err != nil {
			httpx.Fail(w, err)
			return
		}
		users = append(users, u)
	}
	if c.Kind == "direct" {
		c.Name = p.User.Rank + " " + p.User.FullName + " ↔ " + users[0].Rank + " " + users[0].FullName
	}
	ctx := r.Context()
	tx, err := s.db.Begin(ctx)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `INSERT INTO channels(id, name, kind, classification, compartments, unit_code, created_by) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		c.ID, c.Name, c.Kind, c.Classification, c.Compartments, c.Unit, c.CreatedBy); err != nil {
		httpx.Fail(w, err)
		return
	}
	tx.Exec(ctx, `INSERT INTO channel_members(channel_id, user_id, role) VALUES ($1,$2,'owner')`, c.ID, p.User.ID)
	for _, u := range users {
		tx.Exec(ctx, `INSERT INTO channel_members(channel_id, user_id, role) VALUES ($1,$2,'member')`, c.ID, u.ID)
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.Fail(w, err)
		return
	}
	s.audit.Record(ctx, audit.Entry{Actor: p.User.ID.String(), Action: "channel.create", Resource: c.ID.String(), Outcome: "success", IP: p.IP,
		Details: map[string]any{"kind": c.Kind, "classification": c.Classification, "compartments": c.Compartments, "members": len(users) + 1}})
	for _, u := range users {
		s.bus.Notify(u.ID.String(), map[string]any{"type": "channel", "channel": c.ID})
	}
	httpx.JSON(w, 201, c)
}

func (s *Service) handleListChannels(w http.ResponseWriter, r *http.Request) {
	p := identity.FromContext(r.Context())
	rows, err := s.db.Query(r.Context(), `SELECT `+chanCols+`, m.role FROM channels c JOIN channel_members m ON m.channel_id=c.id WHERE m.user_id=$1 ORDER BY c.created_at`, p.User.ID)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	defer rows.Close()
	out := []*Channel{}
	for rows.Next() {
		var role string
		c, err := scanChannel(rows, &role)
		if err != nil {
			httpx.Fail(w, err)
			return
		}
		c.Role = role
		out = append(out, c)
	}
	httpx.JSON(w, 200, out)
}

func (s *Service) members(ctx context.Context, id uuid.UUID) ([]Member, error) {
	rows, err := s.db.Query(ctx, `SELECT u.id, u.service_number, u.full_name, u.rank, u.unit_code, m.role FROM channel_members m JOIN users u ON u.id=m.user_id WHERE m.channel_id=$1 ORDER BY m.added_at`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Member
	for rows.Next() {
		var m Member
		if err := rows.Scan(&m.UserID, &m.ServiceNumber, &m.Name, &m.Rank, &m.Unit, &m.Role); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Service) handleGetChannel(w http.ResponseWriter, r *http.Request) {
	c, role, err := s.authorizeChannel(r, "read")
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	c.Role = role
	c.Members, err = s.members(r.Context(), c.ID)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	httpx.JSON(w, 200, c)
}

func (s *Service) handleAddMember(w http.ResponseWriter, r *http.Request) {
	c, _, err := s.authorizeChannel(r, "manage")
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	if c.Kind != "group" {
		httpx.Fail(w, httpx.E(400, "bad_request", "members can only be added to group channels"))
		return
	}
	var req struct {
		UserID uuid.UUID `json:"user_id"`
	}
	if err := httpx.Decode(r, 4096, &req); err != nil {
		httpx.Fail(w, err)
		return
	}
	u, err := s.eligible(r.Context(), c, req.UserID)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	p := identity.FromContext(r.Context())
	if _, err := s.db.Exec(r.Context(), `INSERT INTO channel_members(channel_id, user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, c.ID, u.ID); err != nil {
		httpx.Fail(w, err)
		return
	}
	s.audit.Record(r.Context(), audit.Entry{Actor: p.User.ID.String(), Action: "channel.member.add", Resource: c.ID.String(), Outcome: "success", IP: p.IP, Details: map[string]any{"user": u.ID.String()}})
	s.bus.Notify(u.ID.String(), map[string]any{"type": "channel", "channel": c.ID})
	w.WriteHeader(204)
}

func (s *Service) handleRemoveMember(w http.ResponseWriter, r *http.Request) {
	c, _, err := s.authorizeChannel(r, "manage")
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	uid, err := uuid.Parse(r.PathValue("user"))
	if err != nil {
		httpx.Fail(w, httpx.E(400, "bad_request", "bad user id"))
		return
	}
	p := identity.FromContext(r.Context())
	if uid == p.User.ID {
		httpx.Fail(w, httpx.E(400, "bad_request", "owners cannot remove themselves"))
		return
	}
	if _, err := s.db.Exec(r.Context(), `DELETE FROM channel_members WHERE channel_id=$1 AND user_id=$2`, c.ID, uid); err != nil {
		httpx.Fail(w, err)
		return
	}
	s.audit.Record(r.Context(), audit.Entry{Actor: p.User.ID.String(), Action: "channel.member.remove", Resource: c.ID.String(), Outcome: "success", IP: p.IP, Details: map[string]any{"user": uid.String()}})
	s.bus.Notify(uid.String(), map[string]any{"type": "channel_removed", "channel": c.ID})
	w.WriteHeader(204)
}

// ---------------------------------------------------------------- MLS

func (s *Service) handleUploadKeyPackages(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CipherSuite int      `json:"cipher_suite"`
		KeyPackages []string `json:"key_packages"`
	}
	if err := httpx.Decode(r, 2<<20, &req); err != nil {
		httpx.Fail(w, err)
		return
	}
	if req.CipherSuite != MLSCipherSuite {
		httpx.Fail(w, httpx.E(400, "bad_request", "only ciphersuite 87 (X-Wing + ML-DSA-87) is accepted"))
		return
	}
	if len(req.KeyPackages) == 0 || len(req.KeyPackages) > 100 {
		httpx.Fail(w, httpx.E(400, "bad_request", "upload 1..100 key packages"))
		return
	}
	p := identity.FromContext(r.Context())
	for _, kp := range req.KeyPackages {
		b, err := base64.StdEncoding.DecodeString(kp)
		if err != nil || len(b) < 64 || len(b) > 32<<10 {
			httpx.Fail(w, httpx.E(400, "bad_request", "malformed key package"))
			return
		}
		if _, err := s.db.Exec(r.Context(), `INSERT INTO key_packages(id, user_id, device_id, cipher_suite, body) VALUES ($1,$2,$3,$4,$5)`, uuid.New(), p.User.ID, p.Device.ID, req.CipherSuite, b); err != nil {
			httpx.Fail(w, err)
			return
		}
	}
	var n int
	s.db.QueryRow(r.Context(), `SELECT count(*) FROM key_packages WHERE user_id=$1 AND device_id=$2 AND consumed_at IS NULL`, p.User.ID, p.Device.ID).Scan(&n)
	httpx.JSON(w, 200, map[string]int{"available": n})
}

func (s *Service) handleKeyPackageCount(w http.ResponseWriter, r *http.Request) {
	p := identity.FromContext(r.Context())
	var n int
	s.db.QueryRow(r.Context(), `SELECT count(*) FROM key_packages WHERE user_id=$1 AND device_id=$2 AND consumed_at IS NULL`, p.User.ID, p.Device.ID).Scan(&n)
	httpx.JSON(w, 200, map[string]int{"available": n})
}

// handleClaimKeyPackage hands out one KeyPackage of a channel member so the
// caller (a channel owner) can add them to the MLS group.
func (s *Service) handleClaimKeyPackage(w http.ResponseWriter, r *http.Request) {
	c, _, err := s.authorizeChannel(r, "write")
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	uid, err := uuid.Parse(r.PathValue("user"))
	if err != nil {
		httpx.Fail(w, httpx.E(400, "bad_request", "bad user id"))
		return
	}
	var isMember bool
	s.db.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM channel_members WHERE channel_id=$1 AND user_id=$2)`, c.ID, uid).Scan(&isMember)
	if !isMember {
		httpx.Fail(w, httpx.E(403, "forbidden", "key packages can only be claimed for channel members"))
		return
	}
	var kp []byte
	// The newest active device of the member is their messaging device.
	err = s.db.QueryRow(r.Context(), `UPDATE key_packages SET consumed_at=now() WHERE id = (
		SELECT k.id FROM key_packages k JOIN devices d ON d.id=k.device_id
		WHERE k.user_id=$1 AND k.consumed_at IS NULL AND d.status='active'
		ORDER BY d.created_at DESC, k.created_at LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING body`, uid).Scan(&kp)
	if errors.Is(err, pgx.ErrNoRows) {
		httpx.Fail(w, httpx.E(409, "no_key_package", "member has no key packages; they must sign in once to publish keys"))
		return
	}
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	httpx.JSON(w, 200, map[string]string{"key_package": base64.StdEncoding.EncodeToString(kp)})
}

type mlsOut struct {
	Seq         int64     `json:"seq"`
	SenderID    uuid.UUID `json:"sender_id"`
	Epoch       int64     `json:"epoch"`
	ContentType string    `json:"content_type"`
	Body        []byte    `json:"body"`
	CreatedAt   time.Time `json:"created_at"`
}

func (s *Service) handlePostMLS(w http.ResponseWriter, r *http.Request) {
	c, _, err := s.authorizeChannel(r, "write")
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	if c.Kind != "group" {
		httpx.Fail(w, httpx.E(400, "bad_request", "MLS messages are for group channels"))
		return
	}
	var req struct {
		Epoch       int64  `json:"epoch"`
		ContentType string `json:"content_type"`
		Body        []byte `json:"body"`
		Welcomes    []struct {
			UserID uuid.UUID `json:"user_id"`
			Body   []byte    `json:"body"`
		} `json:"welcomes"`
	}
	if err := httpx.Decode(r, 4<<20, &req); err != nil {
		httpx.Fail(w, err)
		return
	}
	if req.ContentType != "application" && req.ContentType != "commit" && req.ContentType != "proposal" {
		httpx.Fail(w, httpx.E(400, "bad_request", "content_type must be application, commit or proposal"))
		return
	}
	if len(req.Body) == 0 || len(req.Body) > 1<<20 {
		httpx.Fail(w, httpx.E(400, "bad_request", "body must be 1 byte .. 1 MiB"))
		return
	}
	p := identity.FromContext(r.Context())
	ctx := r.Context()
	tx, err := s.db.Begin(ctx)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	defer tx.Rollback(ctx)
	var epoch int64
	if err := tx.QueryRow(ctx, `SELECT epoch FROM channels WHERE id=$1 FOR UPDATE`, c.ID).Scan(&epoch); err != nil {
		httpx.Fail(w, err)
		return
	}
	if req.Epoch != epoch {
		httpx.Fail(w, httpx.E(409, "epoch_mismatch", "group is at epoch "+strconv.FormatInt(epoch, 10)+"; process pending handshake messages first"))
		return
	}
	var seq int64
	tx.QueryRow(ctx, `SELECT coalesce(max(seq),0) FROM mls_messages WHERE channel_id=$1`, c.ID).Scan(&seq)
	insert := func(ct string, ep int64, recipient *uuid.UUID, body []byte) error {
		seq++
		h := sha256.Sum256(body)
		_, err := tx.Exec(ctx, `INSERT INTO mls_messages(channel_id, seq, sender_id, epoch, content_type, recipient_id, body, body_hash) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			c.ID, seq, p.User.ID, ep, ct, recipient, body, h[:])
		return err
	}
	if err := insert(req.ContentType, req.Epoch, nil, req.Body); err != nil {
		httpx.Fail(w, httpx.E(409, "epoch_conflict", "another commit won this epoch"))
		return
	}
	if req.ContentType == "commit" {
		for _, wl := range req.Welcomes {
			var ok bool
			tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM channel_members WHERE channel_id=$1 AND user_id=$2)`, c.ID, wl.UserID).Scan(&ok)
			if !ok {
				httpx.Fail(w, httpx.E(403, "forbidden", "welcome recipient is not a channel member"))
				return
			}
			rid := wl.UserID
			if err := insert("welcome", req.Epoch+1, &rid, wl.Body); err != nil {
				httpx.Fail(w, err)
				return
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE channels SET epoch=epoch+1 WHERE id=$1`, c.ID); err != nil {
			httpx.Fail(w, err)
			return
		}
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.Fail(w, err)
		return
	}
	if req.ContentType == "commit" {
		s.audit.Record(ctx, audit.Entry{Actor: p.User.ID.String(), Action: "mls.commit", Resource: c.ID.String(), Outcome: "success", IP: p.IP, Details: map[string]any{"epoch": req.Epoch + 1, "welcomes": len(req.Welcomes)}})
	}
	ms, _ := s.members(ctx, c.ID)
	for _, m := range ms {
		s.bus.Notify(m.UserID.String(), map[string]any{"type": "mls", "channel": c.ID, "seq": seq})
	}
	httpx.JSON(w, 201, map[string]int64{"seq": seq})
}

func (s *Service) handleGetMLS(w http.ResponseWriter, r *http.Request) {
	c, _, err := s.authorizeChannel(r, "read")
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	p := identity.FromContext(r.Context())
	rows, err := s.db.Query(r.Context(), `SELECT seq, sender_id, epoch, content_type, body, created_at FROM mls_messages
		WHERE channel_id=$1 AND seq > $2 AND (content_type <> 'welcome' OR recipient_id=$3) ORDER BY seq LIMIT 500`, c.ID, after, p.User.ID)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	defer rows.Close()
	out := []mlsOut{}
	for rows.Next() {
		var m mlsOut
		if err := rows.Scan(&m.Seq, &m.SenderID, &m.Epoch, &m.ContentType, &m.Body, &m.CreatedAt); err != nil {
			httpx.Fail(w, err)
			return
		}
		out = append(out, m)
	}
	httpx.JSON(w, 200, map[string]any{"epoch": c.Epoch, "messages": out})
}

// ---------------------------------------------------------------- Double Ratchet

func (s *Service) handlePutBundle(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IdentitySigPub  []byte `json:"identity_sig_pub"`
		SignedPrekey    []byte `json:"signed_prekey"`
		SignedPrekeyID  int    `json:"signed_prekey_id"`
		SignedPrekeySig []byte `json:"signed_prekey_sig"`
		OneTimePrekeys  []struct {
			ID  int    `json:"id"`
			Pub []byte `json:"pub"`
		} `json:"one_time_prekeys"`
	}
	if err := httpx.Decode(r, 2<<20, &req); err != nil {
		httpx.Fail(w, err)
		return
	}
	if len(req.IdentitySigPub) == 0 || len(req.SignedPrekey) == 0 || len(req.SignedPrekeySig) == 0 || len(req.OneTimePrekeys) > 200 {
		httpx.Fail(w, httpx.E(400, "bad_request", "identity key, signed prekey and signature are required"))
		return
	}
	p := identity.FromContext(r.Context())
	ctx := r.Context()
	tx, err := s.db.Begin(ctx)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	defer tx.Rollback(ctx)
	var prevKey []byte
	tx.QueryRow(ctx, `SELECT identity_sig_pub FROM dr_identities WHERE user_id=$1`, p.User.ID).Scan(&prevKey)
	if _, err := tx.Exec(ctx, `INSERT INTO dr_identities(user_id, device_id, identity_sig_pub, signed_prekey, signed_prekey_id, signed_prekey_sig, updated_at) VALUES ($1,$2,$3,$4,$5,$6,now())
		ON CONFLICT (user_id) DO UPDATE SET device_id=EXCLUDED.device_id, identity_sig_pub=EXCLUDED.identity_sig_pub, signed_prekey=EXCLUDED.signed_prekey, signed_prekey_id=EXCLUDED.signed_prekey_id, signed_prekey_sig=EXCLUDED.signed_prekey_sig, updated_at=now()`,
		p.User.ID, p.Device.ID, req.IdentitySigPub, req.SignedPrekey, req.SignedPrekeyID, req.SignedPrekeySig); err != nil {
		httpx.Fail(w, err)
		return
	}
	if prevKey != nil && string(prevKey) != string(req.IdentitySigPub) {
		tx.Exec(ctx, `DELETE FROM dr_one_time_prekeys WHERE user_id=$1`, p.User.ID)
	}
	for _, k := range req.OneTimePrekeys {
		tx.Exec(ctx, `INSERT INTO dr_one_time_prekeys(user_id, prekey_id, public_key) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`, p.User.ID, k.ID, k.Pub)
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.Fail(w, err)
		return
	}
	if prevKey != nil && string(prevKey) != string(req.IdentitySigPub) {
		s.audit.Record(ctx, audit.Entry{Actor: p.User.ID.String(), Action: "dr.identity.rotate", Outcome: "success", IP: p.IP, Details: map[string]any{"device": p.Device.ID.String()}})
	}
	var n int
	s.db.QueryRow(ctx, `SELECT count(*) FROM dr_one_time_prekeys WHERE user_id=$1 AND consumed_at IS NULL`, p.User.ID).Scan(&n)
	httpx.JSON(w, 200, map[string]int{"one_time_prekeys": n})
}

func (s *Service) handleGetBundle(w http.ResponseWriter, r *http.Request) {
	c, _, err := s.authorizeChannel(r, "write")
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	uid, err := uuid.Parse(r.PathValue("user"))
	if err != nil {
		httpx.Fail(w, httpx.E(400, "bad_request", "bad user id"))
		return
	}
	var isMember bool
	s.db.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM channel_members WHERE channel_id=$1 AND user_id=$2)`, c.ID, uid).Scan(&isMember)
	if !isMember {
		httpx.Fail(w, httpx.E(403, "forbidden", "not a member of this channel"))
		return
	}
	var out struct {
		IdentitySigPub  []byte `json:"identity_sig_pub"`
		SignedPrekey    []byte `json:"signed_prekey"`
		SignedPrekeyID  int    `json:"signed_prekey_id"`
		SignedPrekeySig []byte `json:"signed_prekey_sig"`
		OneTimeID       *int   `json:"one_time_prekey_id,omitempty"`
		OneTime         []byte `json:"one_time_prekey,omitempty"`
	}
	if err := s.db.QueryRow(r.Context(), `SELECT identity_sig_pub, signed_prekey, signed_prekey_id, signed_prekey_sig FROM dr_identities WHERE user_id=$1`, uid).
		Scan(&out.IdentitySigPub, &out.SignedPrekey, &out.SignedPrekeyID, &out.SignedPrekeySig); err != nil {
		httpx.Fail(w, httpx.E(409, "no_bundle", "recipient has not published a prekey bundle yet"))
		return
	}
	var otkID int
	var otk []byte
	if err := s.db.QueryRow(r.Context(), `UPDATE dr_one_time_prekeys SET consumed_at=now() WHERE (user_id, prekey_id) = (
		SELECT user_id, prekey_id FROM dr_one_time_prekeys WHERE user_id=$1 AND consumed_at IS NULL ORDER BY prekey_id LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING prekey_id, public_key`, uid).Scan(&otkID, &otk); err == nil {
		out.OneTimeID, out.OneTime = &otkID, otk
	}
	httpx.JSON(w, 200, out)
}

func (s *Service) handlePostDR(w http.ResponseWriter, r *http.Request) {
	c, _, err := s.authorizeChannel(r, "write")
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	if c.Kind != "direct" {
		httpx.Fail(w, httpx.E(400, "bad_request", "Double Ratchet envelopes are for direct channels"))
		return
	}
	var req struct {
		Envelope []byte `json:"envelope"`
	}
	if err := httpx.Decode(r, 2<<20, &req); err != nil {
		httpx.Fail(w, err)
		return
	}
	if len(req.Envelope) == 0 || len(req.Envelope) > 1<<20 {
		httpx.Fail(w, httpx.E(400, "bad_request", "envelope must be 1 byte .. 1 MiB"))
		return
	}
	p := identity.FromContext(r.Context())
	var other uuid.UUID
	if err := s.db.QueryRow(r.Context(), `SELECT user_id FROM channel_members WHERE channel_id=$1 AND user_id<>$2`, c.ID, p.User.ID).Scan(&other); err != nil {
		httpx.Fail(w, httpx.E(409, "conflict", "direct channel has no peer"))
		return
	}
	var id int64
	if err := s.db.QueryRow(r.Context(), `INSERT INTO dr_messages(channel_id, sender_id, recipient_id, envelope) VALUES ($1,$2,$3,$4) RETURNING id`, c.ID, p.User.ID, other, req.Envelope).Scan(&id); err != nil {
		httpx.Fail(w, err)
		return
	}
	s.bus.Notify(other.String(), map[string]any{"type": "dr", "channel": c.ID, "id": id})
	httpx.JSON(w, 201, map[string]int64{"id": id})
}

func (s *Service) handleGetDR(w http.ResponseWriter, r *http.Request) {
	c, _, err := s.authorizeChannel(r, "read")
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	after, _ := strconv.ParseInt(r.URL.Query().Get("after"), 10, 64)
	p := identity.FromContext(r.Context())
	rows, err := s.db.Query(r.Context(), `SELECT id, sender_id, envelope, created_at FROM dr_messages WHERE channel_id=$1 AND recipient_id=$2 AND id > $3 ORDER BY id LIMIT 500`, c.ID, p.User.ID, after)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	defer rows.Close()
	type msg struct {
		ID        int64     `json:"id"`
		SenderID  uuid.UUID `json:"sender_id"`
		Envelope  []byte    `json:"envelope"`
		CreatedAt time.Time `json:"created_at"`
	}
	out := []msg{}
	var ids []int64
	for rows.Next() {
		var m msg
		if err := rows.Scan(&m.ID, &m.SenderID, &m.Envelope, &m.CreatedAt); err != nil {
			httpx.Fail(w, err)
			return
		}
		out = append(out, m)
		ids = append(ids, m.ID)
	}
	rows.Close()
	if len(ids) > 0 {
		s.db.Exec(r.Context(), `UPDATE dr_messages SET delivered_at=now() WHERE id = ANY($1) AND delivered_at IS NULL`, ids)
	}
	httpx.JSON(w, 200, out)
}

func (s *Service) Routes(mux *http.ServeMux, auth func(http.HandlerFunc) http.Handler) {
	mux.Handle("POST /api/channels", auth(s.handleCreateChannel))
	mux.Handle("GET /api/channels", auth(s.handleListChannels))
	mux.Handle("GET /api/channels/{id}", auth(s.handleGetChannel))
	mux.Handle("POST /api/channels/{id}/members", auth(s.handleAddMember))
	mux.Handle("DELETE /api/channels/{id}/members/{user}", auth(s.handleRemoveMember))
	mux.Handle("POST /api/mls/keypackages", auth(s.handleUploadKeyPackages))
	mux.Handle("GET /api/mls/keypackages/count", auth(s.handleKeyPackageCount))
	mux.Handle("POST /api/channels/{id}/keypackages/{user}", auth(s.handleClaimKeyPackage))
	mux.Handle("POST /api/channels/{id}/mls", auth(s.handlePostMLS))
	mux.Handle("GET /api/channels/{id}/mls", auth(s.handleGetMLS))
	mux.Handle("PUT /api/dr/bundle", auth(s.handlePutBundle))
	mux.Handle("POST /api/channels/{id}/bundle/{user}", auth(s.handleGetBundle))
	mux.Handle("POST /api/channels/{id}/dr", auth(s.handlePostDR))
	mux.Handle("GET /api/channels/{id}/dr", auth(s.handleGetDR))
}
