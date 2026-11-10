// Package files implements encrypted file transfer. Clients encrypt each
// chunk end-to-end (AES-256-GCM under a file key shared inside the MLS /
// Double Ratchet channel) and commit to BLAKE3 hashes of every ciphertext
// chunk in a DPoP-signed manifest before uploading. The server verifies each
// chunk against the manifest, then seals it again at rest under a per-file
// DEK wrapped by a per-file HSM-resident KEK. Destroying that KEK in the
// HSM is cryptographic erasure: no backup of the database or object store
// can recover the file afterwards.
package files

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"lukechampine.com/blake3"

	"github.com/Neurvinch/SIEPMU/server/internal/audit"
	"github.com/Neurvinch/SIEPMU/server/internal/cryptoprov"
	"github.com/Neurvinch/SIEPMU/server/internal/events"
	"github.com/Neurvinch/SIEPMU/server/internal/httpx"
	"github.com/Neurvinch/SIEPMU/server/internal/identity"
	"github.com/Neurvinch/SIEPMU/server/internal/messaging"
	"github.com/Neurvinch/SIEPMU/server/internal/policy"
	"github.com/Neurvinch/SIEPMU/server/internal/store"
)

// ObjectStore stores sealed chunks. The filesystem implementation targets a
// Ceph/MinIO-backed volume mount in production.
type ObjectStore interface {
	Put(key string, data []byte) error
	Get(key string) ([]byte, error)
	DeletePrefix(prefix string) error
	Exists(key string) bool
}

type FSStore struct{ Root string }

func (f FSStore) path(key string) string { return filepath.Join(f.Root, filepath.FromSlash(key)) }

func (f FSStore) Put(key string, data []byte) error {
	p := f.path(key)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}
func (f FSStore) Get(key string) ([]byte, error)   { return os.ReadFile(f.path(key)) }
func (f FSStore) DeletePrefix(prefix string) error { return os.RemoveAll(f.path(prefix)) }
func (f FSStore) Exists(key string) bool {
	_, err := os.Stat(f.path(key))
	return err == nil
}

type Service struct {
	db        *store.Store
	rdb       *redis.Client
	id        *identity.Service
	msg       *messaging.Service
	kms       cryptoprov.KMS
	aead      cryptoprov.AEAD
	obj       ObjectStore
	audit     *audit.Log
	bus       *events.Bus
	maxSize   int64
	chunkSize int
}

func New(db *store.Store, rdb *redis.Client, id *identity.Service, msg *messaging.Service, kms cryptoprov.KMS, p cryptoprov.Provider, obj ObjectStore, al *audit.Log, bus *events.Bus, maxSize int64, chunkSize int) *Service {
	return &Service{db: db, rdb: rdb, id: id, msg: msg, kms: kms, aead: p.AEAD(), obj: obj, audit: al, bus: bus, maxSize: maxSize, chunkSize: chunkSize}
}

type File struct {
	ID             uuid.UUID  `json:"id"`
	OwnerID        uuid.UUID  `json:"owner_id"`
	ChannelID      *uuid.UUID `json:"channel_id"`
	Classification int        `json:"classification"`
	Compartments   []string   `json:"compartments"`
	ChunkSize      int        `json:"chunk_size"`
	ChunkCount     int        `json:"chunk_count"`
	TotalSize      int64      `json:"total_size"`
	ChunkHashes    [][]byte   `json:"chunk_hashes"`
	ManifestHash   []byte     `json:"manifest_hash"`
	Status         string     `json:"status"`
	CreatedAt      time.Time  `json:"created_at"`
	kekID          string
	wrappedDEK     []byte
	unit           string
}

func manifestHash(hashes [][]byte) []byte {
	h := blake3.New(32, nil)
	for i, c := range hashes {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(i))
		h.Write(n[:])
		h.Write(c)
	}
	return h.Sum(nil)
}

func (s *Service) load(ctx context.Context, id uuid.UUID) (*File, error) {
	f := &File{}
	err := s.db.QueryRow(ctx, `SELECT f.id, f.owner_id, f.channel_id, f.classification, f.compartments, f.chunk_size, f.chunk_count, f.total_size, f.chunk_hashes, f.manifest_hash, f.status, f.created_at, f.kek_id, f.wrapped_dek, u.unit_code
		FROM files f JOIN users u ON u.id=f.owner_id WHERE f.id=$1`, id).
		Scan(&f.ID, &f.OwnerID, &f.ChannelID, &f.Classification, &f.Compartments, &f.ChunkSize, &f.ChunkCount, &f.TotalSize, &f.ChunkHashes, &f.ManifestHash, &f.Status, &f.CreatedAt, &f.kekID, &f.wrappedDEK, &f.unit)
	if err != nil {
		return nil, httpx.E(404, "not_found", "file not found")
	}
	return f, nil
}

// authorize checks the caller against the file and its channel membership.
func (s *Service) authorize(r *http.Request, f *File, action string, mutate ...func(*policy.Input)) error {
	p := identity.FromContext(r.Context())
	member := f.OwnerID == p.User.ID
	if f.ChannelID != nil {
		_, role, err := s.msg.LoadChannel(r.Context(), *f.ChannelID, p.User.ID)
		if err == nil && role != "" {
			member = true
		}
	}
	res := policy.Resource{Type: "file", ID: f.ID.String(), Classification: f.Classification, Compartments: f.Compartments,
		Unit: f.unit, Originator: f.OwnerID.String(), Member: member, Owner: f.OwnerID == p.User.ID}
	return s.id.Authorize(r, res, action, mutate...)
}

func (s *Service) handleCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ChannelID      uuid.UUID `json:"channel_id"`
		Classification int       `json:"classification"`
		Compartments   []string  `json:"compartments"`
		TotalSize      int64     `json:"total_size"`
		ChunkSize      int       `json:"chunk_size"`
		ChunkHashes    [][]byte  `json:"chunk_hashes"`
	}
	if err := httpx.Decode(r, 4<<20, &req); err != nil {
		httpx.Fail(w, err)
		return
	}
	p := identity.FromContext(r.Context())
	ctx := r.Context()
	c, role, err := s.msg.LoadChannel(ctx, req.ChannelID, p.User.ID)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	if err := s.id.Authorize(r, c.Resource(role), "write"); err != nil {
		httpx.Fail(w, err)
		return
	}
	if req.Compartments == nil {
		req.Compartments = c.Compartments
	}
	if req.Classification < c.Classification {
		req.Classification = c.Classification // files inherit at least the channel level
	}
	if req.Classification > 4 {
		httpx.Fail(w, httpx.E(400, "bad_request", "classification must be 0..4"))
		return
	}
	if err := s.id.Authorize(r, policy.Resource{Type: "file", Classification: req.Classification, Compartments: req.Compartments, Unit: p.User.Unit}, "create"); err != nil {
		httpx.Fail(w, err)
		return
	}
	if req.ChunkSize <= 0 || req.ChunkSize > 4<<20 {
		httpx.Fail(w, httpx.E(400, "bad_request", "chunk_size must be 1..4 MiB"))
		return
	}
	if req.TotalSize <= 0 || req.TotalSize > s.maxSize {
		httpx.Fail(w, httpx.E(400, "bad_request", fmt.Sprintf("total_size must be 1..%d", s.maxSize)))
		return
	}
	if len(req.ChunkHashes) == 0 || len(req.ChunkHashes) > 1<<16 {
		httpx.Fail(w, httpx.E(400, "bad_request", "chunk_hashes required"))
		return
	}
	for _, h := range req.ChunkHashes {
		if len(h) != 32 {
			httpx.Fail(w, httpx.E(400, "bad_request", "chunk hashes must be 32-byte BLAKE3 digests"))
			return
		}
	}
	id := uuid.New()
	kek, err := s.kms.CreateKEK("file:" + id.String())
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	dek := make([]byte, 32)
	if _, err := ioReadFull(dek); err != nil {
		httpx.Fail(w, err)
		return
	}
	wrapped, err := s.kms.Wrap(kek, dek, id[:])
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	mh := manifestHash(req.ChunkHashes)
	if _, err := s.db.Exec(ctx, `INSERT INTO files(id, owner_id, channel_id, classification, compartments, chunk_size, chunk_count, total_size, chunk_hashes, manifest_hash, kek_id, wrapped_dek)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, id, p.User.ID, c.ID, req.Classification, req.Compartments, req.ChunkSize, len(req.ChunkHashes), req.TotalSize, req.ChunkHashes, mh, kek, wrapped); err != nil {
		s.kms.DestroyKEK(kek)
		httpx.Fail(w, err)
		return
	}
	s.audit.Record(ctx, audit.Entry{Actor: p.User.ID.String(), Action: "file.create", Resource: id.String(), Outcome: "success", IP: p.IP,
		Details: map[string]any{"channel": c.ID.String(), "classification": req.Classification, "size": req.TotalSize, "chunks": len(req.ChunkHashes), "manifest_blake3": fmt.Sprintf("%x", mh)}})
	httpx.JSON(w, 201, map[string]any{"id": id, "manifest_hash": mh})
}

func (s *Service) dek(ctx context.Context, f *File, actor, ip string) ([]byte, error) {
	if f.wrappedDEK == nil || f.Status == "erased" {
		return nil, httpx.E(410, "erased", "file has been cryptographically erased")
	}
	dek, err := s.kms.Unwrap(f.kekID, f.wrappedDEK, f.ID[:])
	if err != nil {
		s.bus.PublishSec(ctx, events.SecEvent{Source: "hsm", Kind: "hsm.unwrap_failure", Severity: 3, UserID: actor, IP: ip, AttackIDs: []string{"T1552"},
			Summary: "HSM failed to unwrap file DEK", Data: map[string]any{"file": f.ID.String(), "kek": f.kekID, "error": err.Error()}})
		return nil, err
	}
	s.bus.PublishSec(ctx, events.SecEvent{Source: "hsm", Kind: "hsm.unwrap", Severity: 0, UserID: actor, IP: ip,
		Summary: "file DEK unwrapped", Data: map[string]any{"file": f.ID.String(), "kek": f.kekID, "classification": f.Classification}})
	return dek, nil
}

func chunkKey(id uuid.UUID, n int) string { return id.String() + "/" + strconv.Itoa(n) }

func chunkAAD(id uuid.UUID, n int) []byte {
	b := append([]byte{}, id[:]...)
	return binary.BigEndian.AppendUint32(b, uint32(n))
}

func (s *Service) handlePutChunk(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Fail(w, httpx.E(400, "bad_request", "bad id"))
		return
	}
	n, err := strconv.Atoi(r.PathValue("n"))
	if err != nil {
		httpx.Fail(w, httpx.E(400, "bad_request", "bad chunk index"))
		return
	}
	ctx := r.Context()
	f, err := s.load(ctx, id)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	p := identity.FromContext(ctx)
	if f.OwnerID != p.User.ID {
		httpx.Fail(w, httpx.E(403, "forbidden", "only the uploader may write chunks"))
		return
	}
	if f.Status != "uploading" {
		httpx.Fail(w, httpx.E(409, "conflict", "file is "+f.Status))
		return
	}
	if n < 0 || n >= f.ChunkCount {
		httpx.Fail(w, httpx.E(400, "bad_request", "chunk index out of range"))
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(f.ChunkSize)+1024))
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	sum := blake3.Sum256(body)
	if !bytes.Equal(sum[:], f.ChunkHashes[n]) {
		s.bus.PublishSec(ctx, events.SecEvent{Source: "files", Kind: "file.integrity_violation", Severity: 3, UserID: p.User.ID.String(), IP: p.IP, AttackIDs: []string{"T1565"},
			Summary: "uploaded chunk does not match signed manifest", Data: map[string]any{"file": id.String(), "chunk": n}})
		httpx.Fail(w, httpx.E(422, "integrity", "chunk BLAKE3 does not match the manifest"))
		return
	}
	dek, err := s.dek(ctx, f, p.User.ID.String(), p.IP)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	sealed, err := s.aead.Seal(dek, body, chunkAAD(id, n))
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	if err := s.obj.Put(chunkKey(id, n), sealed); err != nil {
		httpx.Fail(w, err)
		return
	}
	w.WriteHeader(204)
}

func (s *Service) handleComplete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Fail(w, httpx.E(400, "bad_request", "bad id"))
		return
	}
	ctx := r.Context()
	f, err := s.load(ctx, id)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	p := identity.FromContext(ctx)
	if f.OwnerID != p.User.ID || f.Status != "uploading" {
		httpx.Fail(w, httpx.E(409, "conflict", "not an upload in progress owned by you"))
		return
	}
	for i := 0; i < f.ChunkCount; i++ {
		if !s.obj.Exists(chunkKey(id, i)) {
			httpx.Fail(w, httpx.E(409, "incomplete", fmt.Sprintf("chunk %d missing", i)))
			return
		}
	}
	s.db.Exec(ctx, `UPDATE files SET status='complete' WHERE id=$1`, id)
	s.audit.Record(ctx, audit.Entry{Actor: p.User.ID.String(), Action: "file.complete", Resource: id.String(), Outcome: "success", IP: p.IP})
	w.WriteHeader(204)
}

func (s *Service) handleMeta(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Fail(w, httpx.E(400, "bad_request", "bad id"))
		return
	}
	f, err := s.load(r.Context(), id)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	if err := s.authorize(r, f, "read"); err != nil {
		httpx.Fail(w, err)
		return
	}
	httpx.JSON(w, 200, f)
}

func (s *Service) handleGetChunk(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Fail(w, httpx.E(400, "bad_request", "bad id"))
		return
	}
	n, err := strconv.Atoi(r.PathValue("n"))
	if err != nil {
		httpx.Fail(w, httpx.E(400, "bad_request", "bad chunk index"))
		return
	}
	ctx := r.Context()
	f, err := s.load(ctx, id)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	purpose := r.URL.Query().Get("purpose")
	if err := s.authorize(r, f, "export", func(in *policy.Input) { in.Purpose = purpose }); err != nil {
		httpx.Fail(w, err)
		return
	}
	if f.Status != "complete" {
		httpx.Fail(w, httpx.E(409, "conflict", "file is "+f.Status))
		return
	}
	if n < 0 || n >= f.ChunkCount {
		httpx.Fail(w, httpx.E(400, "bad_request", "chunk index out of range"))
		return
	}
	p := identity.FromContext(ctx)
	dek, err := s.dek(ctx, f, p.User.ID.String(), p.IP)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	sealed, err := s.obj.Get(chunkKey(id, n))
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	pt, err := s.aead.Open(dek, sealed, chunkAAD(id, n))
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	if n == 0 {
		s.audit.Record(ctx, audit.Entry{Actor: p.User.ID.String(), Action: "file.download", Resource: id.String(), Outcome: "success", IP: p.IP, Details: map[string]any{"purpose": purpose, "classification": f.Classification}})
		s.bus.PublishSec(ctx, events.SecEvent{Source: "files", Kind: "file.download", Severity: 0, UserID: p.User.ID.String(), IP: p.IP,
			Summary: "file downloaded", Data: map[string]any{"file": id.String(), "bytes": f.TotalSize, "classification": f.Classification}})
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(pt)
}

func (s *Service) handleApproveErase(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Fail(w, httpx.E(400, "bad_request", "bad id"))
		return
	}
	ctx := r.Context()
	f, err := s.load(ctx, id)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	p := identity.FromContext(ctx)
	if !p.User.HasRole("commander") || p.User.Unit != f.unit {
		httpx.Fail(w, httpx.E(403, "forbidden", "only the owning unit's commander can approve erasure"))
		return
	}
	s.rdb.Set(ctx, "erase-approval:"+id.String(), p.User.ID.String(), 24*time.Hour)
	s.audit.Record(ctx, audit.Entry{Actor: p.User.ID.String(), Action: "file.erase.approve", Resource: id.String(), Outcome: "success", IP: p.IP})
	s.id.Notify(ctx, f.OwnerID, "erase_approved", "Commander approved erasure of a file you own", id.String())
	w.WriteHeader(204)
}

func (s *Service) handleErase(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Fail(w, httpx.E(400, "bad_request", "bad id"))
		return
	}
	ctx := r.Context()
	f, err := s.load(ctx, id)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	approver, _ := s.rdb.Get(ctx, "erase-approval:"+id.String()).Result()
	if err := s.authorize(r, f, "erase", func(in *policy.Input) { in.Approval.Commander = approver != "" }); err != nil {
		httpx.Fail(w, err)
		return
	}
	if f.Status == "erased" {
		httpx.Fail(w, httpx.E(409, "conflict", "already erased"))
		return
	}
	p := identity.FromContext(ctx)
	if err := s.kms.DestroyKEK(f.kekID); err != nil {
		httpx.Fail(w, fmt.Errorf("destroy KEK: %w", err))
		return
	}
	s.db.Exec(ctx, `UPDATE files SET status='erased', wrapped_dek=NULL, erased_at=now(), erased_by=$2 WHERE id=$1`, id, p.User.ID)
	if err := s.obj.DeletePrefix(id.String()); err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Printf("files: delete sealed chunks of %s: %v\n", id, err)
	}
	s.rdb.Del(ctx, "erase-approval:"+id.String())
	s.audit.Record(ctx, audit.Entry{Actor: p.User.ID.String(), Action: "file.crypto_erase", Resource: id.String(), Outcome: "success", IP: p.IP, Details: map[string]any{"kek_destroyed": f.kekID, "approved_by": approver}})
	w.WriteHeader(204)
}

func (s *Service) handleListChannelFiles(w http.ResponseWriter, r *http.Request) {
	cid, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.Fail(w, httpx.E(400, "bad_request", "bad id"))
		return
	}
	p := identity.FromContext(r.Context())
	c, role, err := s.msg.LoadChannel(r.Context(), cid, p.User.ID)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	if err := s.id.Authorize(r, c.Resource(role), "read"); err != nil {
		httpx.Fail(w, err)
		return
	}
	rows, err := s.db.Query(r.Context(), `SELECT id, owner_id, classification, total_size, chunk_count, status, created_at FROM files WHERE channel_id=$1 ORDER BY created_at DESC LIMIT 500`, cid)
	if err != nil {
		httpx.Fail(w, err)
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, owner uuid.UUID
		var cl, cc int
		var size int64
		var st string
		var ts time.Time
		rows.Scan(&id, &owner, &cl, &size, &cc, &st, &ts)
		out = append(out, map[string]any{"id": id, "owner_id": owner, "classification": cl, "total_size": size, "chunk_count": cc, "status": st, "created_at": ts})
	}
	httpx.JSON(w, 200, out)
}

func (s *Service) Routes(mux *http.ServeMux, auth func(http.HandlerFunc) http.Handler) {
	mux.Handle("POST /api/files", auth(s.handleCreate))
	mux.Handle("PUT /api/files/{id}/chunks/{n}", auth(s.handlePutChunk))
	mux.Handle("POST /api/files/{id}/complete", auth(s.handleComplete))
	mux.Handle("GET /api/files/{id}", auth(s.handleMeta))
	mux.Handle("GET /api/files/{id}/chunks/{n}", auth(s.handleGetChunk))
	mux.Handle("POST /api/files/{id}/erase-approval", auth(s.handleApproveErase))
	mux.Handle("POST /api/files/{id}/erase", auth(s.handleErase))
	mux.Handle("GET /api/channels/{id}/files", auth(s.handleListChannelFiles))
}
