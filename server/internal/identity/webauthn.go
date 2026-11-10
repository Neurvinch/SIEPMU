package identity

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Neurvinch/SIEPMU/server/internal/audit"
	"github.com/Neurvinch/SIEPMU/server/internal/httpx"
	"github.com/Neurvinch/SIEPMU/server/internal/pki"
)

type ceremony struct {
	Kind    string               `json:"kind"`
	UserID  uuid.UUID            `json:"user_id"`
	Session webauthn.SessionData `json:"session"`
}

func (s *Service) putCeremony(r *http.Request, c ceremony) (string, error) {
	id := uuid.NewString()
	b, _ := json.Marshal(c)
	return id, s.rdb.Set(r.Context(), "wa:"+id, b, 5*time.Minute).Err()
}

func (s *Service) takeCeremony(r *http.Request, kind string) (*ceremony, error) {
	id := r.URL.Query().Get("ceremony")
	b, err := s.rdb.GetDel(r.Context(), "wa:"+id).Bytes()
	if err != nil {
		return nil, httpx.E(http.StatusBadRequest, "ceremony_expired", "authentication ceremony not found or expired")
	}
	var c ceremony
	if err := json.Unmarshal(b, &c); err != nil || c.Kind != kind {
		return nil, httpx.E(http.StatusBadRequest, "ceremony_invalid", "ceremony type mismatch")
	}
	return &c, nil
}

// NewEnrollmentCode returns a human-typable one-time code and its hash.
func NewEnrollmentCode() (string, []byte) {
	b := make([]byte, 15)
	rand.Read(b)
	code := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
	code = code[0:6] + "-" + code[6:12] + "-" + code[12:18] + "-" + code[18:24]
	h := sha256.Sum256([]byte(code))
	return code, h[:]
}

func normaliseCode(c string) string { return strings.ToUpper(strings.TrimSpace(c)) }

// --------------------------------------------------------------- enrolment

func (s *Service) handleEnrollBegin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ServiceNumber string `json:"service_number"`
		EnrollCode    string `json:"enroll_code"`
	}
	if err := httpx.Decode(r, 4096, &req); err != nil {
		httpx.Fail(w, err)
		return
	}
	ip := httpx.ClientIP(r)
	var id uuid.UUID
	var codeHash []byte
	var exp *time.Time
	var status string
	err := s.db.QueryRow(r.Context(), `SELECT id, enroll_code_hash, enroll_expires_at, status FROM users WHERE service_number=$1`, req.ServiceNumber).Scan(&id, &codeHash, &exp, &status)
	h := sha256.Sum256([]byte(normaliseCode(req.EnrollCode)))
	if err != nil || codeHash == nil || exp == nil || time.Now().After(*exp) || subtle.ConstantTimeCompare(codeHash, h[:]) != 1 {
		s.secEvent(r.Context(), "auth.enroll_failure", 2, "", ip, []string{"T1110"}, "invalid enrolment code for "+req.ServiceNumber, map[string]any{"service_number": req.ServiceNumber})
		httpx.Fail(w, httpx.E(http.StatusUnauthorized, "enroll_invalid", "enrolment code invalid or expired"))
		return
	}
	u, err := s.UserByID(r.Context(), id)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	if err := s.loadCredentials(r.Context(), u); err != nil {
		httpx.Fail(w, err)
		return
	}
	var excl []protocol.CredentialDescriptor
	for _, c := range u.creds {
		excl = append(excl, c.Descriptor())
	}
	opts, sd, err := s.wa.BeginRegistration(u, webauthn.WithExclusions(excl),
		webauthn.WithCredentialParameters([]protocol.CredentialParameter{
			{Type: protocol.PublicKeyCredentialType, Algorithm: -7},   // ES256
			{Type: protocol.PublicKeyCredentialType, Algorithm: -8},   // EdDSA
			{Type: protocol.PublicKeyCredentialType, Algorithm: -257}, // RS256 (smart-card/TPM)
		}))
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	cid, err := s.putCeremony(r, ceremony{Kind: "enroll", UserID: u.ID, Session: *sd})
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	httpx.JSON(w, 200, map[string]any{"ceremony": cid, "options": opts})
}

func (s *Service) handleEnrollFinish(w http.ResponseWriter, r *http.Request) {
	body, err := readAndRestoreBody(r, 64<<10)
	if err != nil {
		httpx.Fail(w, httpx.E(413, "too_large", err.Error()))
		return
	}
	proof, err := s.VerifyDPoP(r, body)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	c, err := s.takeCeremony(r, "enroll")
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	u, err := s.UserByID(r.Context(), c.UserID)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(body))
	if err != nil {
		httpx.Fail(w, httpx.E(400, "webauthn_invalid", err.Error()))
		return
	}
	cred, err := s.wa.CreateCredential(u, c.Session, parsed)
	if err != nil {
		s.secEvent(r.Context(), "auth.enroll_failure", 2, u.ID.String(), httpx.ClientIP(r), nil, "WebAuthn registration failed: "+err.Error(), nil)
		httpx.Fail(w, httpx.E(400, "webauthn_failed", err.Error()))
		return
	}
	if !cred.Flags.UserVerified {
		httpx.Fail(w, httpx.E(400, "uv_required", "authenticator did not perform user verification"))
		return
	}
	cj, _ := json.Marshal(cred)
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	defer tx.Rollback(r.Context())
	if _, err := tx.Exec(r.Context(), `INSERT INTO webauthn_credentials(id, user_id, credential_json, aaguid, attestation_fmt) VALUES ($1,$2,$3,$4,$5)`,
		cred.ID, u.ID, cj, cred.Authenticator.AAGUID, cred.AttestationFormat); err != nil {
		httpx.Fail(w, err)
		return
	}
	// The enrolment code is handed over in person on a managed terminal, so
	// the device that redeems it is provisioned as managed and active.
	dev, err := s.createDevice(r, tx, u, proof.PublicKey(), proofJWK(proof), true)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	if _, err := tx.Exec(r.Context(), `UPDATE users SET status='active', enroll_code_hash=NULL, enroll_expires_at=NULL WHERE id=$1`, u.ID); err != nil {
		httpx.Fail(w, err)
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		httpx.Fail(w, err)
		return
	}
	s.audit.Record(r.Context(), audit.Entry{Actor: u.ID.String(), Action: "identity.enroll", Resource: dev.ID.String(), Outcome: "success", IP: httpx.ClientIP(r),
		Details: map[string]any{"credential_id": base64.RawURLEncoding.EncodeToString(cred.ID), "aaguid": base64.RawURLEncoding.EncodeToString(cred.Authenticator.AAGUID), "attestation": cred.AttestationFormat, "backup_eligible": cred.Flags.BackupEligible}})
	u.Status = "active"
	s.startSession(w, r, u, dev, "webauthn", proof.PublicKey())
}

// --------------------------------------------------------------- login

func (s *Service) handleLoginBegin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ServiceNumber string `json:"service_number"`
	}
	if err := httpx.Decode(r, 4096, &req); err != nil {
		httpx.Fail(w, err)
		return
	}
	u, err := s.userByServiceNumber(r.Context(), req.ServiceNumber)
	if err == nil {
		err = s.loadCredentials(r.Context(), u)
	}
	if err != nil || len(u.creds) == 0 {
		s.secEvent(r.Context(), "auth.unknown_user", 1, "", httpx.ClientIP(r), []string{"T1087"}, "login attempt for unknown or unenrolled service number "+req.ServiceNumber, map[string]any{"service_number": req.ServiceNumber})
		httpx.Fail(w, httpx.E(http.StatusUnauthorized, "login_failed", "no enrolled authenticator for this service number"))
		return
	}
	opts, sd, err := s.wa.BeginLogin(u, webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	cid, err := s.putCeremony(r, ceremony{Kind: "login", UserID: u.ID, Session: *sd})
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	httpx.JSON(w, 200, map[string]any{"ceremony": cid, "options": opts})
}

func (s *Service) handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	ip := httpx.ClientIP(r)
	body, err := readAndRestoreBody(r, 64<<10)
	if err != nil {
		httpx.Fail(w, httpx.E(413, "too_large", err.Error()))
		return
	}
	proof, err := s.VerifyDPoP(r, body)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	c, err := s.takeCeremony(r, "login")
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	u, err := s.UserByID(r.Context(), c.UserID)
	if err == nil {
		err = s.loadCredentials(r.Context(), u)
	}
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(body))
	if err != nil {
		httpx.Fail(w, httpx.E(400, "webauthn_invalid", err.Error()))
		return
	}
	cred, err := s.wa.ValidateLogin(u, c.Session, parsed)
	if err != nil || !parsed.Response.AuthenticatorData.Flags.HasUserVerified() {
		msg := "user verification missing"
		if err != nil {
			msg = err.Error()
		}
		s.secEvent(r.Context(), "auth.webauthn_failure", 2, u.ID.String(), ip, []string{"T1110"}, "FIDO2 assertion failed: "+msg, nil)
		s.audit.Record(r.Context(), audit.Entry{Actor: u.ID.String(), Action: "identity.login", Outcome: "failure", IP: ip, Details: map[string]any{"error": msg}})
		httpx.Fail(w, httpx.E(http.StatusUnauthorized, "login_failed", "authenticator assertion rejected"))
		return
	}
	if cred.Authenticator.CloneWarning {
		s.secEvent(r.Context(), "auth.authenticator_clone", 4, u.ID.String(), ip, []string{"T1556"}, "authenticator signature counter regressed: possible cloned key", map[string]any{"credential_id": base64.RawURLEncoding.EncodeToString(cred.ID)})
		httpx.Fail(w, httpx.E(http.StatusUnauthorized, "authenticator_cloned", "authenticator counter anomaly; contact the SOC"))
		return
	}
	if u.Status != "active" {
		httpx.Fail(w, httpx.E(http.StatusForbidden, "user_suspended", "account is not active"))
		return
	}
	cj, _ := json.Marshal(cred)
	s.db.Exec(r.Context(), `UPDATE webauthn_credentials SET credential_json=$2, last_used_at=now() WHERE id=$1`, cred.ID, cj)

	var dev *Device
	dev, err = scanDevice(s.db.QueryRow(r.Context(), `SELECT `+deviceCols+` FROM devices WHERE jkt=$1`, proof.PublicKey()))
	if errors.Is(err, pgx.ErrNoRows) {
		tx, err := s.db.Begin(r.Context())
		if err != nil {
			httpx.Fail(w, err)
			return
		}
		defer tx.Rollback(r.Context())
		dev, err = s.createDevice(r, tx, u, proof.PublicKey(), proofJWK(proof), false)
		if err != nil {
			httpx.Fail(w, err)
			return
		}
		if err := tx.Commit(r.Context()); err != nil {
			httpx.Fail(w, err)
			return
		}
		s.secEvent(r.Context(), "device.new", 1, u.ID.String(), ip, nil, "login from a new device; awaiting approval", map[string]any{"device_id": dev.ID.String(), "user_agent": dev.UserAgent})
		s.notifyRole(r, "admin", "device_pending", u.Rank+" "+u.FullName+" requests approval for device "+dev.Label, dev.ID.String())
	} else if err != nil {
		httpx.Fail(w, err)
		return
	} else if dev.UserID != u.ID {
		s.secEvent(r.Context(), "device.key_reuse", 4, u.ID.String(), ip, []string{"T1550"}, "device key bound to another user presented at login", map[string]any{"device_id": dev.ID.String()})
		httpx.Fail(w, httpx.E(http.StatusForbidden, "device_mismatch", "device key belongs to another user"))
		return
	}
	if dev.Status == "revoked" {
		httpx.Fail(w, httpx.E(http.StatusForbidden, "device_revoked", "this device has been revoked"))
		return
	}
	s.startSession(w, r, u, dev, "webauthn", proof.PublicKey())
}

// smartcardStrength upgrades MFA strength when a PIV/CAC client certificate
// verified at the TLS layer belongs to the same service number.
func (s *Service) smartcardStrength(r *http.Request, u *User) (int, string) {
	if s.scPool == nil || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return 2, "webauthn"
	}
	leaf := r.TLS.PeerCertificates[0]
	inter := x509Pool(r.TLS.PeerCertificates[1:])
	if _, err := leaf.Verify(x509VerifyOpts(s.scPool, inter)); err != nil {
		return 2, "webauthn"
	}
	if leaf.Subject.SerialNumber == u.ServiceNumber {
		return 3, "smartcard+webauthn"
	}
	return 2, "webauthn"
}

func (s *Service) startSession(w http.ResponseWriter, r *http.Request, u *User, dev *Device, _ string, jkt string) {
	ctx := r.Context()
	ip := httpx.ClientIP(r)
	strength, method := s.smartcardStrength(r, u)
	lat, lon := ParseGeo(r.Header.Get("X-SIEPMU-Geo"))
	refresh := make([]byte, 32)
	rand.Read(refresh)
	rh := sha256.Sum256(refresh)
	sid := uuid.New()
	now := time.Now()
	// Previous session location for impossible-travel analysis.
	var plat, plon *float64
	var pts *time.Time
	s.db.QueryRow(ctx, `SELECT lat, lon, created_at FROM sessions WHERE user_id=$1 AND lat IS NOT NULL ORDER BY created_at DESC LIMIT 1`, u.ID).Scan(&plat, &plon, &pts)
	if _, err := s.db.Exec(ctx, `INSERT INTO sessions(id, user_id, device_id, auth_method, mfa_strength, refresh_hash, ip, lat, lon, expires_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		sid, u.ID, dev.ID, method, strength, rh[:], ip, lat, lon, now.Add(s.cfg.SessionTTL)); err != nil {
		httpx.Fail(w, err)
		return
	}
	at, err := s.issueAccessToken(u.ID, sid, dev.ID, jkt)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	data := map[string]any{"session_id": sid.String(), "device_id": dev.ID.String(), "method": method, "user_agent": r.Header.Get("User-Agent")}
	if lat != nil {
		data["lat"], data["lon"] = *lat, *lon
	}
	if plat != nil && pts != nil {
		data["prev_lat"], data["prev_lon"], data["prev_time"] = *plat, *plon, pts.UTC().Format(time.RFC3339)
	}
	s.secEvent(ctx, "auth.login_success", 0, u.ID.String(), ip, nil, u.ServiceNumber+" authenticated with "+method, data)
	s.audit.Record(ctx, audit.Entry{Actor: u.ID.String(), Action: "identity.session.create", Resource: sid.String(), Outcome: "success", IP: ip, Details: map[string]any{"device": dev.ID.String(), "method": method, "mfa_strength": strength}})
	httpx.JSON(w, 200, map[string]any{
		"access_token":  at,
		"token_type":    "DPoP",
		"expires_in":    int(s.cfg.AccessTokenTTL.Seconds()),
		"refresh_token": base64.RawURLEncoding.EncodeToString(sid[:]) + "." + base64.RawURLEncoding.EncodeToString(refresh),
		"device_status": dev.Status,
		"user":          u,
	})
}

func (s *Service) handleRefresh(w http.ResponseWriter, r *http.Request) {
	body, err := readAndRestoreBody(r, 4096)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	proof, err := s.VerifyDPoP(r, body)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		httpx.Fail(w, httpx.E(400, "bad_request", "invalid body"))
		return
	}
	parts := strings.Split(req.RefreshToken, ".")
	if len(parts) != 2 {
		httpx.Fail(w, httpx.E(401, "refresh_invalid", "malformed refresh token"))
		return
	}
	sidb, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	secret, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	if err1 != nil || err2 != nil || len(sidb) != 16 {
		httpx.Fail(w, httpx.E(401, "refresh_invalid", "malformed refresh token"))
		return
	}
	sid, _ := uuid.FromBytes(sidb)
	ctx := r.Context()
	var stored []byte
	var uid, did uuid.UUID
	var exp, last time.Time
	var revoked *time.Time
	var jkt string
	err = s.db.QueryRow(ctx, `SELECT s.refresh_hash, s.user_id, s.device_id, s.expires_at, s.last_active_at, s.revoked_at, d.jkt FROM sessions s JOIN devices d ON d.id=s.device_id WHERE s.id=$1`, sid).
		Scan(&stored, &uid, &did, &exp, &last, &revoked, &jkt)
	h := sha256.Sum256(secret)
	if err != nil || revoked != nil || time.Now().After(exp) || time.Since(last) > s.cfg.SessionIdleTTL {
		httpx.Fail(w, httpx.E(401, "session_expired", "session expired; authenticate again"))
		return
	}
	if subtle.ConstantTimeCompare(stored, h[:]) != 1 {
		// Refresh-token reuse means the token was stolen: kill the session.
		s.db.Exec(ctx, `UPDATE sessions SET revoked_at=now(), revoked_reason='refresh token reuse' WHERE id=$1`, sid)
		s.secEvent(ctx, "auth.refresh_reuse", 4, uid.String(), httpx.ClientIP(r), []string{"T1550.001"}, "rotated refresh token replayed; session revoked", map[string]any{"session_id": sid.String()})
		httpx.Fail(w, httpx.E(401, "refresh_reused", "refresh token reuse detected; session revoked"))
		return
	}
	if jkt != proof.PublicKey() {
		httpx.Fail(w, httpx.E(401, "device_mismatch", "refresh must be proven by the session device key"))
		return
	}
	next := make([]byte, 32)
	rand.Read(next)
	nh := sha256.Sum256(next)
	if _, err := s.db.Exec(ctx, `UPDATE sessions SET refresh_hash=$2, last_active_at=now() WHERE id=$1`, sid, nh[:]); err != nil {
		httpx.Fail(w, err)
		return
	}
	at, err := s.issueAccessToken(uid, sid, did, jkt)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	httpx.JSON(w, 200, map[string]any{"access_token": at, "token_type": "DPoP", "expires_in": int(s.cfg.AccessTokenTTL.Seconds()),
		"refresh_token": parts[0] + "." + base64.RawURLEncoding.EncodeToString(next)})
}

func (s *Service) handleLogout(w http.ResponseWriter, r *http.Request) {
	p := FromContext(r.Context())
	s.db.Exec(r.Context(), `UPDATE sessions SET revoked_at=now(), revoked_reason='logout' WHERE id=$1`, p.Session.ID)
	s.audit.Record(r.Context(), audit.Entry{Actor: p.User.ID.String(), Action: "identity.session.logout", Resource: p.Session.ID.String(), Outcome: "success", IP: p.IP})
	w.WriteHeader(http.StatusNoContent)
}

// createDevice records a device and, when pre-approved, issues its
// certificate from the internal CA.
func (s *Service) createDevice(r *http.Request, tx pgx.Tx, u *User, jkt string, jwk map[string]any, approved bool) (*Device, error) {
	jwkJSON, _ := json.Marshal(jwk)
	label := strings.TrimSpace(r.Header.Get("X-SIEPMU-Device-Label"))
	if label == "" {
		fam, v := BrowserVersion(r.Header.Get("User-Agent"))
		label = fam + " " + itoa(v)
	}
	if len(label) > 80 {
		label = label[:80]
	}
	d := &Device{ID: uuid.New(), UserID: u.ID, JKT: jkt, Label: label, UserAgent: r.Header.Get("User-Agent"), Managed: approved, Status: "pending", CreatedAt: time.Now()}
	if approved {
		d.Status = "active"
	}
	if _, err := tx.Exec(r.Context(), `INSERT INTO devices(id, user_id, jkt, public_jwk, label, user_agent, managed, status) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		d.ID, u.ID, jkt, jwkJSON, d.Label, d.UserAgent, d.Managed, d.Status); err != nil {
		return nil, err
	}
	if approved {
		if err := s.issueDeviceCert(r, tx, d, u, jwk); err != nil {
			return nil, err
		}
	}
	return d, nil
}

func (s *Service) issueDeviceCert(r *http.Request, tx pgx.Tx, d *Device, u *User, jwk map[string]any) error {
	pub, err := ecJWKToPublic(jwk)
	if err != nil {
		return httpx.E(400, "device_key", err.Error())
	}
	fam, _ := BrowserVersion(d.UserAgent)
	cert, err := s.CA.IssueDevice(pub, pki.DeviceAttributes{DeviceID: d.ID.String(), ServiceNumber: u.ServiceNumber, Platform: fam}, 365*24*time.Hour)
	if err != nil {
		return err
	}
	d.CertSerial = cert.SerialNumber.Text(16)
	_, err = tx.Exec(r.Context(), `UPDATE devices SET cert_der=$2, cert_serial=$3 WHERE id=$1`, d.ID, cert.Raw, d.CertSerial)
	return err
}

func ecJWKToPublic(jwk map[string]any) (*ecdsa.PublicKey, error) {
	if jwk["kty"] != "EC" || jwk["crv"] != "P-256" {
		return nil, errors.New("device keys must be EC P-256")
	}
	xs, _ := jwk["x"].(string)
	ys, _ := jwk["y"].(string)
	x, err1 := base64.RawURLEncoding.DecodeString(xs)
	y, err2 := base64.RawURLEncoding.DecodeString(ys)
	if err1 != nil || err2 != nil {
		return nil, errors.New("bad JWK coordinates")
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return nil, errors.New("JWK point not on curve")
	}
	return pub, nil
}

func itoa(v int) string { return big.NewInt(int64(v)).String() }
