// Package legacy is the mesh side of the legacy integration bridge: the
// content-validation gate for inbound envelopes, the outbound queue, and the
// member-facing API of 'legacy' channels.
package legacy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/Neurvinch/SIEPMU/server/internal/audit"
	"github.com/Neurvinch/SIEPMU/server/internal/bridge"
	"github.com/Neurvinch/SIEPMU/server/internal/cryptoprov"
	"github.com/Neurvinch/SIEPMU/server/internal/events"
	"github.com/Neurvinch/SIEPMU/server/internal/httpx"
	"github.com/Neurvinch/SIEPMU/server/internal/identity"
	"github.com/Neurvinch/SIEPMU/server/internal/messaging"
	"github.com/Neurvinch/SIEPMU/server/internal/pki"
	"github.com/Neurvinch/SIEPMU/server/internal/policy"
	"github.com/Neurvinch/SIEPMU/server/internal/store"
)

// KEK seals legacy message bodies at rest.
const KEK = "kek-legacy"

const maxBody = 64 << 10

type Service struct {
	db    *store.Store
	id    *identity.Service
	msg   *messaging.Service
	kms   cryptoprov.KMS
	v     cryptoprov.Verifier
	audit *audit.Log
	bus   *events.Bus
	clock bridge.HLC
}

func New(db *store.Store, id *identity.Service, msg *messaging.Service, kms cryptoprov.KMS, v cryptoprov.Verifier, al *audit.Log, bus *events.Bus) *Service {
	return &Service{db: db, id: id, msg: msg, kms: kms, v: v, audit: al, bus: bus}
}

// bridgeIdentity authenticates the calling bridge from its mTLS SVID.
func (s *Service) bridgeIdentity(r *http.Request) (name string, pub []byte, err error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", nil, httpx.E(401, "unauthenticated", "mTLS workload certificate required")
	}
	wid, err := pki.WorkloadIdentity(r.TLS.PeerCertificates[0])
	if err != nil || !strings.HasPrefix(wid, "bridge/") {
		return "", nil, httpx.E(403, "forbidden", "caller is not a bridge workload")
	}
	name = strings.TrimPrefix(wid, "bridge/")
	if err := s.db.QueryRow(r.Context(), `UPDATE bridges SET last_seen_at=now() WHERE name=$1 RETURNING public_key`, name).Scan(&pub); err != nil {
		return "", nil, httpx.E(403, "forbidden", "bridge "+name+" is not registered")
	}
	return name, pub, nil
}

// validate is the content-validation gate. It returns a rejection reason or "".
func validate(e *bridge.Envelope, channelClass int) string {
	switch {
	case e.Body == "":
		return "empty or unparseable message"
	case len(e.Body) > maxBody:
		return "message exceeds 64 KiB"
	case !utf8.ValidString(e.Body):
		return "body is not valid UTF-8"
	case e.Classification < 0 || e.Classification > 4:
		return "invalid classification"
	case e.Classification > channelClass:
		return fmt.Sprintf("message classification %d exceeds channel ceiling %d", e.Classification, channelClass)
	case bridge.Rank(e.Precedence) == 3 && e.Precedence != "ROUTINE":
		return "unknown precedence"
	case e.HLC>>16 > time.Now().Add(5*time.Minute).UnixMilli():
		return "timestamp is in the future"
	}
	for _, r := range e.Body {
		if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
			return "body contains control characters"
		}
	}
	low := strings.ToLower(e.Body)
	for _, bad := range []string{"<script", "javascript:", "\x1b["} {
		if strings.Contains(low, bad) {
			return "body contains active content"
		}
	}
	return ""
}

// HandleInbound serves POST /mesh/bridge/inbound. The batch is merged into
// the grow-only message set: replays are acknowledged as duplicates.
func (s *Service) HandleInbound(w http.ResponseWriter, r *http.Request) {
	name, pub, err := s.bridgeIdentity(r)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	var batch []bridge.Signed
	if err := httpx.Decode(r, 8<<20, &batch); err != nil {
		httpx.Fail(w, err)
		return
	}
	ctx := r.Context()
	verdicts := map[string]string{}
	for _, sg := range batch {
		verdicts[sg.ID] = s.ingest(ctx, name, pub, sg)
	}
	httpx.JSON(w, 200, verdicts)
}

func (s *Service) ingest(ctx context.Context, name string, pub []byte, sg bridge.Signed) string {
	var prior string
	if s.db.QueryRow(ctx, `SELECT verdict FROM bridge_messages WHERE id=$1`, sg.ID).Scan(&prior) == nil {
		return "duplicate"
	}
	reject := func(reason string, e *bridge.Envelope) string {
		s.db.Exec(ctx, `INSERT INTO bridge_messages(id, adapter, verdict) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`, sg.ID, adapterOf(e), "rejected: "+reason)
		data := map[string]any{"bridge": name, "id": sg.ID, "reason": reason}
		if e != nil {
			data["adapter"], data["origin"], data["destination"] = e.Adapter, e.Origin, e.Destination
		}
		s.bus.PublishSec(ctx, events.SecEvent{Source: "bridge", Kind: "bridge.rejected", Severity: 2, AttackIDs: []string{"T1027"}, Summary: "legacy message rejected by validation gate: " + reason, Data: data})
		return "rejected: " + reason
	}
	e, err := bridge.Verify(s.v, pub, sg)
	if err != nil {
		return reject("bad envelope signature", nil)
	}
	if e.Bridge != name {
		return reject("envelope names a different bridge", e)
	}
	var cid uuid.UUID
	var class int
	if err := s.db.QueryRow(ctx, `SELECT c.id, c.classification FROM bridge_routes r JOIN channels c ON c.id=r.channel_id WHERE r.bridge=$1 AND r.adapter=$2 AND (r.address=$3 OR r.address=$4 OR r.address='*') ORDER BY (r.address='*') LIMIT 1`,
		name, e.Adapter, e.Destination, e.Origin).Scan(&cid, &class); err != nil {
		return reject("no route for "+e.Adapter+" "+e.Destination, e)
	}
	if reason := validate(e, class); reason != "" {
		return reject(reason, e)
	}
	sealed, err := s.kms.Wrap(KEK, []byte(e.Body), []byte(sg.ID))
	if err != nil {
		return "retry: " + err.Error()
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return "retry: " + err.Error()
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `INSERT INTO legacy_messages(id, channel_id, direction, bridge, adapter, hlc, origin, destination, precedence, classification, sealed_body) VALUES ($1,$2,'inbound',$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT (id) DO NOTHING`,
		sg.ID, cid, name, e.Adapter, e.HLC, e.Origin, e.Destination, e.Precedence, e.Classification, sealed); err != nil {
		return "retry: " + err.Error()
	}
	tx.Exec(ctx, `INSERT INTO bridge_messages(id, adapter, channel_id, verdict) VALUES ($1,$2,$3,'accepted') ON CONFLICT DO NOTHING`, sg.ID, e.Adapter, cid)
	if err := tx.Commit(ctx); err != nil {
		return "retry: " + err.Error()
	}
	s.clock.Observe(e.HLC)
	s.audit.Record(ctx, audit.Entry{Actor: "bridge/" + name, Action: "bridge.inbound", Resource: sg.ID, Outcome: "success",
		Details: map[string]any{"adapter": e.Adapter, "origin": e.Origin, "channel": cid.String(), "precedence": e.Precedence, "classification": e.Classification}})
	rows, _ := s.db.Query(ctx, `SELECT user_id FROM channel_members WHERE channel_id=$1`, cid)
	if rows != nil {
		var ids []uuid.UUID
		for rows.Next() {
			var u uuid.UUID
			rows.Scan(&u)
			ids = append(ids, u)
		}
		rows.Close()
		for _, u := range ids {
			s.bus.Notify(u.String(), map[string]any{"type": "legacy", "channel": cid, "precedence": e.Precedence})
		}
	}
	return "accepted"
}

func adapterOf(e *bridge.Envelope) string {
	if e == nil {
		return "unknown"
	}
	return e.Adapter
}

type outbound struct {
	ID          string `json:"id"`
	Adapter     string `json:"adapter"`
	Destination string `json:"destination"`
	Body        string `json:"body"`
}

// HandleOutbound serves GET /mesh/bridge/outbound: queued traffic for the bridge.
func (s *Service) HandleOutbound(w http.ResponseWriter, r *http.Request) {
	name, _, err := s.bridgeIdentity(r)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	rows, err := s.db.Query(r.Context(), `SELECT id, adapter, destination, sealed_body FROM legacy_messages WHERE bridge=$1 AND status='queued'
		ORDER BY CASE precedence WHEN 'FLASH' THEN 0 WHEN 'IMMEDIATE' THEN 1 WHEN 'PRIORITY' THEN 2 ELSE 3 END, hlc LIMIT 50`, name)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	defer rows.Close()
	out := []outbound{}
	for rows.Next() {
		var o outbound
		var sealed []byte
		if err := rows.Scan(&o.ID, &o.Adapter, &o.Destination, &sealed); err != nil {
			httpx.Fail(w, err)
			return
		}
		body, err := s.kms.Unwrap(KEK, sealed, []byte(o.ID))
		if err != nil {
			continue
		}
		o.Body = string(body)
		out = append(out, o)
	}
	httpx.JSON(w, 200, out)
}

// HandleOutboundAck serves POST /mesh/bridge/outbound/ack.
func (s *Service) HandleOutboundAck(w http.ResponseWriter, r *http.Request) {
	name, _, err := s.bridgeIdentity(r)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	var ids []string
	if err := httpx.Decode(r, 1<<20, &ids); err != nil {
		httpx.Fail(w, err)
		return
	}
	s.db.Exec(r.Context(), `UPDATE legacy_messages SET status='sent', sent_at=now() WHERE bridge=$1 AND id = ANY($2) AND status='queued'`, name, ids)
	rows, _ := s.db.Query(r.Context(), `SELECT DISTINCT m.user_id, l.channel_id FROM legacy_messages l JOIN channel_members m ON m.channel_id=l.channel_id WHERE l.id = ANY($1)`, ids)
	if rows != nil {
		type pair struct{ u, c uuid.UUID }
		var ps []pair
		for rows.Next() {
			var p pair
			rows.Scan(&p.u, &p.c)
			ps = append(ps, p)
		}
		rows.Close()
		for _, p := range ps {
			s.bus.Notify(p.u.String(), map[string]any{"type": "legacy", "channel": p.c})
		}
	}
	w.WriteHeader(204)
}

// ------------------------------------------------------------ member API

func (s *Service) channel(r *http.Request, action string) (*messaging.Channel, error) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return nil, httpx.E(400, "bad_request", "bad channel id")
	}
	p := identity.FromContext(r.Context())
	c, role, err := s.msg.LoadChannel(r.Context(), id, p.User.ID)
	if err != nil {
		return nil, err
	}
	if c.Kind != "legacy" {
		return nil, httpx.E(400, "bad_request", "not a legacy channel")
	}
	return c, s.id.Authorize(r, c.Resource(role), action)
}

func (s *Service) handleList(w http.ResponseWriter, r *http.Request) {
	c, err := s.channel(r, "read")
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	rows, err := s.db.Query(r.Context(), `SELECT * FROM (SELECT l.id, l.direction, l.adapter, l.hlc, l.origin, l.destination, l.precedence, l.classification, l.sealed_body, l.status, l.created_at, coalesce(u.rank||' '||u.full_name,'')
		FROM legacy_messages l LEFT JOIN users u ON u.id=l.sender_id WHERE l.channel_id=$1 ORDER BY l.hlc DESC, l.id LIMIT 300) t ORDER BY hlc, id`, c.ID)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, dir, adapter, origin, dest, prec, status, sender string
		var hlc int64
		var class int
		var sealed []byte
		var created time.Time
		if err := rows.Scan(&id, &dir, &adapter, &hlc, &origin, &dest, &prec, &class, &sealed, &status, &created, &sender); err != nil {
			httpx.Fail(w, err)
			return
		}
		body, err := s.kms.Unwrap(KEK, sealed, []byte(id))
		if err != nil {
			continue
		}
		out = append(out, map[string]any{"id": id, "direction": dir, "adapter": adapter, "hlc": hlc, "origin": origin, "destination": dest, "precedence": prec,
			"classification": class, "body": string(body), "status": status, "created_at": created, "sender": sender})
	}
	httpx.JSON(w, 200, out)
}

func (s *Service) handleSend(w http.ResponseWriter, r *http.Request) {
	c, err := s.channel(r, "write")
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	var req struct {
		Body       string `json:"body"`
		Precedence string `json:"precedence"`
	}
	if err := httpx.Decode(r, 128<<10, &req); err != nil {
		httpx.Fail(w, err)
		return
	}
	if req.Precedence == "" {
		req.Precedence = "ROUTINE"
	}
	ctx := r.Context()
	p := identity.FromContext(ctx)
	var br, adapter, address string
	if err := s.db.QueryRow(ctx, `SELECT bridge, adapter, address FROM bridge_routes WHERE channel_id=$1 LIMIT 1`, c.ID).Scan(&br, &adapter, &address); err != nil {
		httpx.Fail(w, httpx.E(409, "no_route", "channel has no bridge route"))
		return
	}
	e := bridge.Envelope{Bridge: br, Adapter: adapter, Origin: p.User.ServiceNumber, Destination: address, Precedence: req.Precedence, Classification: c.Classification, HLC: s.clock.Now(), Body: req.Body}
	if reason := validate(&e, c.Classification); reason != "" {
		httpx.Fail(w, httpx.E(422, "rejected", reason))
		return
	}
	body := req.Body
	if adapter == "acp127" { // formatted traffic carries its marking in-band
		body = strings.ToUpper(identity.Levels[c.Classification]) + "\n" + body
	}
	raw, _ := json.Marshal(e)
	id := uuid.NewSHA1(uuid.NameSpaceOID, raw).String()
	sealed, err := s.kms.Wrap(KEK, []byte(body), []byte(id))
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	if _, err := s.db.Exec(ctx, `INSERT INTO legacy_messages(id, channel_id, direction, bridge, adapter, hlc, origin, destination, precedence, classification, sealed_body, sender_id, status) VALUES ($1,$2,'outbound',$3,$4,$5,$6,$7,$8,$9,$10,$11,'queued')`,
		id, c.ID, br, adapter, e.HLC, e.Origin, address, e.Precedence, c.Classification, sealed, p.User.ID); err != nil {
		httpx.Fail(w, err)
		return
	}
	s.audit.Record(ctx, audit.Entry{Actor: p.User.ID.String(), Action: "bridge.outbound", Resource: id, Outcome: "queued", IP: p.IP, Details: map[string]any{"channel": c.ID.String(), "adapter": adapter, "destination": address, "precedence": e.Precedence}})
	httpx.JSON(w, 201, map[string]string{"id": id, "status": "queued"})
}

// handleCreateRoute lets an admin create a legacy channel bound to a route.
func (s *Service) handleCreateRoute(w http.ResponseWriter, r *http.Request) {
	if err := s.id.Authorize(r, policy.Resource{Type: "admin"}, "manage"); err != nil {
		httpx.Fail(w, err)
		return
	}
	var req struct {
		Name           string      `json:"name"`
		Bridge         string      `json:"bridge"`
		Adapter        string      `json:"adapter"`
		Address        string      `json:"address"`
		Classification int         `json:"classification"`
		Members        []uuid.UUID `json:"members"`
	}
	if err := httpx.Decode(r, 16<<10, &req); err != nil {
		httpx.Fail(w, err)
		return
	}
	if req.Name == "" || req.Address == "" || (req.Adapter != "ax25" && req.Adapter != "acp127" && req.Adapter != "sbd") || req.Classification < 0 || req.Classification > 4 {
		httpx.Fail(w, httpx.E(400, "bad_request", "name, bridge, adapter (ax25|acp127|sbd), address and classification are required"))
		return
	}
	ctx := r.Context()
	p := identity.FromContext(ctx)
	tx, err := s.db.Begin(ctx)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	defer tx.Rollback(ctx)
	cid := uuid.New()
	if _, err := tx.Exec(ctx, `INSERT INTO channels(id, name, kind, classification, unit_code, created_by) VALUES ($1,$2,'legacy',$3,$4,$5)`, cid, req.Name, req.Classification, p.User.Unit, p.User.ID); err != nil {
		httpx.Fail(w, err)
		return
	}
	if _, err := tx.Exec(ctx, `INSERT INTO bridge_routes(bridge, adapter, address, channel_id) VALUES ($1,$2,$3,$4)`, req.Bridge, req.Adapter, req.Address, cid); err != nil {
		httpx.Fail(w, httpx.E(400, "bad_request", "bridge is not registered or the route already exists"))
		return
	}
	tx.Exec(ctx, `INSERT INTO channel_members(channel_id, user_id, role) VALUES ($1,$2,'owner')`, cid, p.User.ID)
	for _, m := range req.Members {
		var cl int
		if tx.QueryRow(ctx, `SELECT clearance FROM users WHERE id=$1 AND status='active'`, m).Scan(&cl) != nil || cl < req.Classification {
			httpx.Fail(w, httpx.E(409, "ineligible", "a listed member is not active or lacks clearance"))
			return
		}
		tx.Exec(ctx, `INSERT INTO channel_members(channel_id, user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`, cid, m)
	}
	if err := tx.Commit(ctx); err != nil {
		httpx.Fail(w, err)
		return
	}
	s.audit.Record(ctx, audit.Entry{Actor: p.User.ID.String(), Action: "bridge.route.create", Resource: cid.String(), Outcome: "success", IP: p.IP, Details: map[string]any{"bridge": req.Bridge, "adapter": req.Adapter, "address": req.Address}})
	httpx.JSON(w, 201, map[string]any{"channel_id": cid})
}

func (s *Service) handleBridges(w http.ResponseWriter, r *http.Request) {
	if err := s.id.Authorize(r, policy.Resource{Type: "admin"}, "read"); err != nil {
		httpx.Fail(w, err)
		return
	}
	rows, err := s.db.Query(r.Context(), `SELECT b.name, b.last_seen_at, (SELECT count(*) FROM bridge_routes r WHERE r.bridge=b.name), (SELECT count(*) FROM legacy_messages l WHERE l.bridge=b.name AND l.status='queued') FROM bridges b ORDER BY b.name`)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var n string
		var seen *time.Time
		var routes, queued int
		rows.Scan(&n, &seen, &routes, &queued)
		out = append(out, map[string]any{"name": n, "last_seen_at": seen, "routes": routes, "queued_outbound": queued})
	}
	httpx.JSON(w, 200, out)
}

func (s *Service) Routes(mux *http.ServeMux, auth func(http.HandlerFunc) http.Handler) {
	mux.Handle("GET /api/channels/{id}/legacy", auth(s.handleList))
	mux.Handle("POST /api/channels/{id}/legacy", auth(s.handleSend))
	mux.Handle("POST /api/admin/bridge-routes", auth(s.handleCreateRoute))
	mux.Handle("GET /api/admin/bridges", auth(s.handleBridges))
}
