// Package identity is Ring 2 (DMZ / auth ring): FIDO2/WebAuthn and smart-card
// authentication, device trust, DPoP-bound short-lived tokens, session state
// and break-glass. There is no password login anywhere in the platform.
package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	dpop "github.com/AxisCommunications/go-dpop"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"

	"github.com/Neurvinch/SIEPMU/server/internal/audit"
	"github.com/Neurvinch/SIEPMU/server/internal/config"
	"github.com/Neurvinch/SIEPMU/server/internal/events"
	"github.com/Neurvinch/SIEPMU/server/internal/httpx"
	"github.com/Neurvinch/SIEPMU/server/internal/pki"
	"github.com/Neurvinch/SIEPMU/server/internal/policy"
	"github.com/Neurvinch/SIEPMU/server/internal/store"
)

var Levels = []string{"UNCLASSIFIED", "RESTRICTED", "CONFIDENTIAL", "SECRET", "TOP SECRET"}

type User struct {
	ID            uuid.UUID `json:"id"`
	ServiceNumber string    `json:"service_number"`
	FullName      string    `json:"full_name"`
	Rank          string    `json:"rank"`
	Unit          string    `json:"unit"`
	Clearance     int       `json:"clearance"`
	Compartments  []string  `json:"compartments"`
	Roles         []string  `json:"roles"`
	Status        string    `json:"status"`
	Handle        []byte    `json:"-"`
	creds         []webauthn.Credential
}

func (u *User) WebAuthnID() []byte                         { return u.Handle }
func (u *User) WebAuthnName() string                       { return u.ServiceNumber }
func (u *User) WebAuthnDisplayName() string                { return u.Rank + " " + u.FullName }
func (u *User) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func (u *User) HasRole(r string) bool {
	for _, x := range u.Roles {
		if x == r {
			return true
		}
	}
	return false
}

type Device struct {
	ID         uuid.UUID  `json:"id"`
	UserID     uuid.UUID  `json:"user_id"`
	JKT        string     `json:"jkt"`
	Label      string     `json:"label"`
	UserAgent  string     `json:"user_agent"`
	Managed    bool       `json:"managed"`
	Status     string     `json:"status"`
	CertSerial string     `json:"cert_serial,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LastSeen   *time.Time `json:"last_seen_at,omitempty"`
}

type Session struct {
	ID           uuid.UUID
	UserID       uuid.UUID
	DeviceID     uuid.UUID
	AuthMethod   string
	MFAStrength  int
	IP           string
	Lat, Lon     *float64
	CreatedAt    time.Time
	LastActive   time.Time
	ExpiresAt    time.Time
	RevokedAt    *time.Time
	BreakglassID *uuid.UUID
}

// Principal is the authenticated caller attached to each request context.
type Principal struct {
	User          *User
	Device        *Device
	Session       *Session
	HardwareBound bool
	Patched       bool
	Geofence      string
	Risk          int
	Breakglass    *policy.Breakglass
	IP            string
}

type ctxKey struct{}

func FromContext(ctx context.Context) *Principal {
	p, _ := ctx.Value(ctxKey{}).(*Principal)
	return p
}

// WithPrincipal is used by tests and mesh-internal callers.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

type Service struct {
	cfg      *config.Config
	db       *store.Store
	rdb      *redis.Client
	wa       *webauthn.WebAuthn
	tokenKey ed25519.PrivateKey
	CA       *pki.CA
	audit    *audit.Log
	bus      *events.Bus
	pol      *policy.Engine
	scPool   *x509.CertPool
	origin   *url.URL
}

func New(cfg *config.Config, db *store.Store, rdb *redis.Client, tokenSeed []byte, ca *pki.CA, al *audit.Log, bus *events.Bus, pol *policy.Engine, smartcardPool *x509.CertPool) (*Service, error) {
	wa, err := webauthn.New(&webauthn.Config{
		RPID:                  cfg.RPID,
		RPDisplayName:         cfg.RPName,
		RPOrigins:             []string{cfg.PublicOrigin},
		AttestationPreference: protocol.PreferDirectAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification: protocol.VerificationRequired,
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
		},
	})
	if err != nil {
		return nil, err
	}
	o, err := url.Parse(cfg.PublicOrigin)
	if err != nil {
		return nil, err
	}
	return &Service{cfg: cfg, db: db, rdb: rdb, wa: wa, tokenKey: ed25519.NewKeyFromSeed(tokenSeed), CA: ca, audit: al, bus: bus, pol: pol, scPool: smartcardPool, origin: o}, nil
}

// ---------------------------------------------------------------- loaders

const userCols = `id, service_number, full_name, rank, unit_code, clearance, compartments, roles, status, webauthn_handle`

func scanUser(row pgx.Row) (*User, error) {
	u := &User{}
	err := row.Scan(&u.ID, &u.ServiceNumber, &u.FullName, &u.Rank, &u.Unit, &u.Clearance, &u.Compartments, &u.Roles, &u.Status, &u.Handle)
	return u, err
}

func (s *Service) UserByID(ctx context.Context, id uuid.UUID) (*User, error) {
	return scanUser(s.db.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE id=$1`, id))
}

func (s *Service) userByServiceNumber(ctx context.Context, sn string) (*User, error) {
	return scanUser(s.db.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE service_number=$1`, sn))
}

func (s *Service) userByHandle(ctx context.Context, h []byte) (*User, error) {
	return scanUser(s.db.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE webauthn_handle=$1`, h))
}

func (s *Service) loadCredentials(ctx context.Context, u *User) error {
	rows, err := s.db.Query(ctx, `SELECT credential_json FROM webauthn_credentials WHERE user_id=$1`, u.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	u.creds = nil
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return err
		}
		var c webauthn.Credential
		if err := json.Unmarshal(raw, &c); err != nil {
			return err
		}
		u.creds = append(u.creds, c)
	}
	return rows.Err()
}

const deviceCols = `id, user_id, jkt, label, user_agent, managed, status, coalesce(cert_serial,''), created_at, last_seen_at`

func scanDevice(row pgx.Row) (*Device, error) {
	d := &Device{}
	err := row.Scan(&d.ID, &d.UserID, &d.JKT, &d.Label, &d.UserAgent, &d.Managed, &d.Status, &d.CertSerial, &d.CreatedAt, &d.LastSeen)
	return d, err
}

func (s *Service) loadSession(ctx context.Context, id uuid.UUID) (*Session, error) {
	ss := &Session{}
	err := s.db.QueryRow(ctx, `SELECT id, user_id, device_id, auth_method, mfa_strength, ip, lat, lon, created_at, last_active_at, expires_at, revoked_at, breakglass_id FROM sessions WHERE id=$1`, id).
		Scan(&ss.ID, &ss.UserID, &ss.DeviceID, &ss.AuthMethod, &ss.MFAStrength, &ss.IP, &ss.Lat, &ss.Lon, &ss.CreatedAt, &ss.LastActive, &ss.ExpiresAt, &ss.RevokedAt, &ss.BreakglassID)
	return ss, err
}

// ---------------------------------------------------------------- tokens

type AccessClaims struct {
	dpop.BoundAccessTokenClaims
	SID string `json:"sid"`
	DID string `json:"did"`
}

func (s *Service) issueAccessToken(userID, sessionID, deviceID uuid.UUID, jkt string) (string, error) {
	now := time.Now()
	c := AccessClaims{
		BoundAccessTokenClaims: dpop.BoundAccessTokenClaims{
			RegisteredClaims: &jwt.RegisteredClaims{
				Issuer:    s.cfg.PublicOrigin,
				Subject:   userID.String(),
				Audience:  jwt.ClaimStrings{s.cfg.PublicOrigin + "/api"},
				IssuedAt:  jwt.NewNumericDate(now),
				NotBefore: jwt.NewNumericDate(now.Add(-5 * time.Second)),
				ExpiresAt: jwt.NewNumericDate(now.Add(s.cfg.AccessTokenTTL)),
				ID:        uuid.NewString(),
			},
			Confirmation: dpop.Confirmation{JWKThumbprint: jkt},
		},
		SID: sessionID.String(),
		DID: deviceID.String(),
	}
	return jwt.NewWithClaims(jwt.SigningMethodEdDSA, &c).SignedString(s.tokenKey)
}

func (s *Service) parseAccessToken(tok string) (*jwt.Token, *AccessClaims, error) {
	c := &AccessClaims{BoundAccessTokenClaims: dpop.BoundAccessTokenClaims{RegisteredClaims: &jwt.RegisteredClaims{}}}
	t, err := jwt.ParseWithClaims(tok, c, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodEdDSA {
			return nil, errors.New("unexpected signing method")
		}
		return s.tokenKey.Public(), nil
	}, jwt.WithIssuer(s.cfg.PublicOrigin), jwt.WithAudience(s.cfg.PublicOrigin+"/api"), jwt.WithExpirationRequired())
	if err != nil {
		return nil, nil, err
	}
	return t, c, nil
}

// requestURL reconstructs the public URL the client addressed (for htu).
func (s *Service) requestURL(r *http.Request) *url.URL {
	u := *s.origin
	u.Path = r.URL.Path
	return &u
}

// VerifyDPoP checks the DPoP proof on a request (RFC 9449 §4.3), including
// replay protection on jti and an optional body-hash claim "bh".
func (s *Service) VerifyDPoP(r *http.Request, body []byte) (*dpop.Proof, error) {
	proofs := r.Header.Values("DPoP")
	if len(proofs) != 1 {
		return nil, httpx.E(http.StatusUnauthorized, "dpop_required", "exactly one DPoP proof header is required")
	}
	skew := 30 * time.Second
	age := 60 * time.Second
	p, err := dpop.Parse(proofs[0], dpop.HTTPVerb(r.Method), s.requestURL(r), dpop.ParseOptions{TimeWindow: &skew, AllowedProofAge: &age})
	if err != nil {
		return nil, httpx.E(http.StatusUnauthorized, "dpop_invalid", err.Error())
	}
	claims := p.Claims.(*dpop.ProofTokenClaims)
	ok, err := s.rdb.SetNX(r.Context(), "dpop:jti:"+claims.ID, 1, 2*age).Result()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, httpx.E(http.StatusUnauthorized, "dpop_replay", "DPoP proof already used")
	}
	if body != nil {
		parts := strings.Split(proofs[0], ".")
		raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var extra struct {
			BH string `json:"bh"`
		}
		_ = json.Unmarshal(raw, &extra)
		sum := sha256.Sum256(body)
		if extra.BH != base64.RawURLEncoding.EncodeToString(sum[:]) {
			return nil, httpx.E(http.StatusUnauthorized, "request_signature", "request body hash (bh) does not match signed DPoP proof")
		}
	}
	return p, nil
}

func proofJWK(p *dpop.Proof) map[string]any {
	jwk, _ := p.Header["jwk"].(map[string]any)
	return jwk
}

// ---------------------------------------------------------------- middleware

// Authenticate validates the DPoP-bound access token, loads the principal
// and enforces session/device state. allowPendingDevice lets a caller whose
// device awaits approval reach the self-service status endpoint only.
func (s *Service) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := s.authenticate(r)
		if err != nil {
			s.secEvent(r.Context(), "auth.token_rejected", 1, "", httpx.ClientIP(r), nil, "access token rejected: "+err.Error(), map[string]any{"path": r.URL.Path})
			httpx.Fail(w, err)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, p)))
	})
}

// bodyMethods are verified against the DPoP "bh" claim.
func hasBody(m string) bool {
	return m == http.MethodPost || m == http.MethodPut || m == http.MethodPatch
}

func (s *Service) authenticate(r *http.Request) (*Principal, error) {
	ctx := r.Context()
	authz := r.Header.Get("Authorization")
	tok, ok := strings.CutPrefix(authz, "DPoP ")
	if !ok {
		// WebSocket upgrades cannot set headers from browsers; they pass the
		// token and a proof as query parameters instead.
		if r.Header.Get("Upgrade") == "websocket" && r.URL.Query().Get("access_token") != "" {
			tok = r.URL.Query().Get("access_token")
			r.Header.Set("DPoP", r.URL.Query().Get("dpop"))
		} else {
			return nil, httpx.E(http.StatusUnauthorized, "unauthenticated", "DPoP-bound access token required")
		}
	}
	t, claims, err := s.parseAccessToken(tok)
	if err != nil {
		return nil, httpx.E(http.StatusUnauthorized, "token_invalid", err.Error())
	}
	var body []byte
	if hasBody(r.Method) && !strings.HasPrefix(r.Header.Get("Content-Type"), "application/octet-stream") {
		body, err = readAndRestoreBody(r, 4<<20)
		if err != nil {
			return nil, httpx.E(http.StatusRequestEntityTooLarge, "body_too_large", err.Error())
		}
	}
	proof, err := s.VerifyDPoP(r, body)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(tok))
	if err := proof.Validate([]byte(base64.RawURLEncoding.EncodeToString(sum[:])), t); err != nil {
		return nil, httpx.E(http.StatusUnauthorized, "dpop_binding", err.Error())
	}
	sid, _ := uuid.Parse(claims.SID)
	sess, err := s.loadSession(ctx, sid)
	if err != nil {
		return nil, httpx.E(http.StatusUnauthorized, "session_invalid", "session not found")
	}
	now := time.Now()
	if sess.RevokedAt != nil {
		return nil, httpx.E(http.StatusUnauthorized, "session_revoked", "session has been revoked")
	}
	if now.After(sess.ExpiresAt) || now.Sub(sess.LastActive) > s.cfg.SessionIdleTTL {
		return nil, httpx.E(http.StatusUnauthorized, "session_expired", "session expired; authenticate again")
	}
	u, err := s.UserByID(ctx, sess.UserID)
	if err != nil {
		return nil, err
	}
	if u.Status != "active" {
		return nil, httpx.E(http.StatusForbidden, "user_suspended", "account is not active")
	}
	d, err := scanDevice(s.db.QueryRow(ctx, `SELECT `+deviceCols+` FROM devices WHERE id=$1`, sess.DeviceID))
	if err != nil {
		return nil, err
	}
	if d.JKT != proof.PublicKey() {
		return nil, httpx.E(http.StatusUnauthorized, "device_mismatch", "proof key does not belong to the session device")
	}
	if d.Status == "revoked" {
		return nil, httpx.E(http.StatusForbidden, "device_revoked", "device has been revoked")
	}
	if d.Status != "active" && r.URL.Path != "/api/me" {
		return nil, httpx.E(http.StatusForbidden, "device_pending", "device awaits administrator approval")
	}
	if _, err := s.db.Exec(ctx, `UPDATE sessions SET last_active_at=now() WHERE id=$1`, sess.ID); err != nil {
		return nil, err
	}
	s.db.Exec(ctx, `UPDATE devices SET last_seen_at=now() WHERE id=$1`, d.ID)
	p := &Principal{User: u, Device: d, Session: sess, IP: httpx.ClientIP(r)}
	p.Patched = Patched(r.Header.Get("User-Agent"), s.cfg.MinBrowser)
	lat, lon := ParseGeo(r.Header.Get("X-SIEPMU-Geo"))
	if lat == nil {
		lat, lon = sess.Lat, sess.Lon
	}
	p.Geofence = Geofence(lat, lon, s.cfg.Geofences)
	var be bool
	_ = s.db.QueryRow(ctx, `SELECT bool_and(NOT coalesce((credential_json->'flags'->>'backupEligible')::bool, false)) FROM webauthn_credentials WHERE user_id=$1`, u.ID).Scan(&be)
	p.HardwareBound = be
	if v, err := s.rdb.Get(ctx, "risk:"+u.ID.String()).Result(); err == nil {
		p.Risk, _ = strconv.Atoi(v)
	}
	if sess.BreakglassID != nil {
		var bg policy.Breakglass
		var exp time.Time
		err := s.db.QueryRow(ctx, `SELECT grant_clearance, grant_compartments, expires_at FROM breakglass_requests WHERE id=$1 AND status='active'`, *sess.BreakglassID).Scan(&bg.Clearance, &bg.Compartments, &exp)
		if err == nil && now.Before(exp) {
			p.Breakglass = &bg
		}
	}
	return p, nil
}

// PolicyInput builds the ABAC input for the principal.
func (p *Principal) PolicyInput(res policy.Resource, action string) policy.Input {
	in := policy.Input{
		Subject: policy.Subject{
			ID: p.User.ID.String(), ServiceNumber: p.User.ServiceNumber, Rank: p.User.Rank, Unit: p.User.Unit,
			Clearance: p.User.Clearance, Compartments: p.User.Compartments, Roles: p.User.Roles, Status: p.User.Status,
		},
		Device: policy.Device{
			ID: p.Device.ID.String(), Managed: p.Device.Managed && p.Device.Status == "active",
			HardwareBound: p.HardwareBound, Patched: p.Patched, Geofence: p.Geofence,
		},
		Session: policy.Session{
			MFAStrength: p.Session.MFAStrength, Risk: p.Risk,
			AgeSeconds: int64(time.Since(p.Session.CreatedAt).Seconds()), Breakglass: p.Breakglass,
		},
		Resource: res,
		Action:   action,
	}
	return in
}

// Authorize evaluates policy for the caller; every denial is a signed audit
// event and a security event for the monitoring fabric.
func (s *Service) Authorize(r *http.Request, res policy.Resource, action string, mutate ...func(*policy.Input)) error {
	p := FromContext(r.Context())
	if p == nil {
		return httpx.E(http.StatusUnauthorized, "unauthenticated", "no principal")
	}
	in := p.PolicyInput(res, action)
	for _, m := range mutate {
		m(&in)
	}
	d, err := s.pol.Evaluate(r.Context(), in)
	if err != nil {
		return err
	}
	if !d.Allow {
		s.audit.Record(r.Context(), audit.Entry{Actor: p.User.ID.String(), Action: "authz." + res.Type + "." + action, Resource: res.ID, Outcome: "deny", IP: p.IP, Details: map[string]any{"reasons": d.Reasons, "classification": res.Classification}})
		s.secEvent(r.Context(), "policy.deny", 2, p.User.ID.String(), p.IP, nil, fmt.Sprintf("policy denied %s on %s: %s", action, res.Type, strings.Join(d.Reasons, "; ")), map[string]any{"resource": res.ID, "reasons": d.Reasons, "classification": res.Classification})
		e := httpx.E(http.StatusForbidden, "forbidden", "access denied by policy")
		e.Reasons = d.Reasons
		return e
	}
	return nil
}

func (s *Service) secEvent(ctx context.Context, kind string, sev int, user, ip string, attack []string, summary string, data map[string]any) {
	if s.bus == nil {
		return
	}
	if err := s.bus.PublishSec(ctx, events.SecEvent{Source: "identity", Kind: kind, Severity: sev, UserID: user, IP: ip, AttackIDs: attack, Summary: summary, Data: data}); err != nil {
		fmt.Printf("identity: publish sec event: %v\n", err)
	}
}

// RevokeUserSessions is the SOAR containment action "suspend session".
func (s *Service) RevokeUserSessions(ctx context.Context, userID uuid.UUID, reason string) (int64, error) {
	tag, err := s.db.Exec(ctx, `UPDATE sessions SET revoked_at=now(), revoked_reason=$2 WHERE user_id=$1 AND revoked_at IS NULL`, userID, reason)
	if err != nil {
		return 0, err
	}
	s.bus.Notify(userID.String(), map[string]any{"type": "session_revoked", "reason": reason})
	return tag.RowsAffected(), nil
}
