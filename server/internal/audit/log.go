// Package audit implements the signed, append-only Merkle audit log. Leaves
// and every perfect-subtree node are persisted, so inclusion and
// consistency proofs (RFC 6962 / RFC 9162) can be served for any tree size;
// tree heads are signed with the composite ML-DSA-65 + Ed25519 key.
package audit

import (
	"context"
	"crypto"
	_ "crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/transparency-dev/merkle/compact"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"

	"github.com/Neurvinch/SIEPMU/server/internal/cryptoprov"
	"github.com/Neurvinch/SIEPMU/server/internal/store"
)

// Origin identifies this log in signed checkpoints.
const Origin = "siepmu.iaf/audit/v1"

// Entry is one audit record. It is serialised to canonical JSON (struct
// field order, no HTML escaping) before hashing.
type Entry struct {
	Time     time.Time      `json:"time"`
	Actor    string         `json:"actor"`
	Action   string         `json:"action"`
	Resource string         `json:"resource,omitempty"`
	Outcome  string         `json:"outcome"`
	IP       string         `json:"ip,omitempty"`
	Details  map[string]any `json:"details,omitempty"`
}

// TreeHead is a signed checkpoint.
type TreeHead struct {
	Size      uint64    `json:"size"`
	RootHash  []byte    `json:"root_hash"`
	Time      time.Time `json:"time"`
	Signature []byte    `json:"signature"`
	PublicKey []byte    `json:"public_key"`
	Algorithm string    `json:"algorithm"`
}

// CheckpointBody is the exact byte string that is signed.
func CheckpointBody(size uint64, root []byte, ts time.Time) []byte {
	return []byte(fmt.Sprintf("%s\n%d\n%s\n%d\n", Origin, size, base64.StdEncoding.EncodeToString(root), ts.UnixMilli()))
}

type Log struct {
	db     *store.Store
	signer cryptoprov.Signer
	hasher *rfc6962.Hasher
	rf     *compact.RangeFactory

	mu    sync.Mutex
	rng   *compact.Range
	dirty bool

	// OnAppend, if set, is invoked after each committed append (used to feed
	// the monitoring fabric). It must not block.
	OnAppend func(idx uint64, e Entry)
}

func New(ctx context.Context, db *store.Store, signer cryptoprov.Signer) (*Log, error) {
	h := rfc6962.New(crypto.SHA256)
	l := &Log{db: db, signer: signer, hasher: h, rf: &compact.RangeFactory{Hash: h.HashChildren}}
	if err := l.reload(ctx, db); err != nil {
		return nil, err
	}
	return l, nil
}

type querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// reload rebuilds the compact range for the right edge of the stored tree.
func (l *Log) reload(ctx context.Context, q querier) error {
	var size uint64
	if err := q.QueryRow(ctx, `SELECT count(*) FROM audit_leaves`).Scan(&size); err != nil {
		return err
	}
	ids := compact.RangeNodes(0, size, nil)
	hashes := make([][]byte, len(ids))
	for i, id := range ids {
		if err := q.QueryRow(ctx, `SELECT hash FROM audit_nodes WHERE level=$1 AND idx=$2`, int(id.Level), int64(id.Index)).Scan(&hashes[i]); err != nil {
			return fmt.Errorf("audit: missing node %v: %w", id, err)
		}
	}
	r, err := l.rf.NewRange(0, size, hashes)
	if err != nil {
		return err
	}
	l.rng = r
	return nil
}

// Append durably records an entry and returns its leaf index.
func (l *Log) Append(ctx context.Context, e Entry) (uint64, error) {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	raw, err := canonicalJSON(e)
	if err != nil {
		return 0, err
	}
	leaf := l.hasher.HashLeaf(raw)

	l.mu.Lock()
	defer l.mu.Unlock()

	tx, err := l.db.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	// Serialise writers across replicas, then make sure our in-memory right
	// edge matches the database (another replica may have appended).
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(424242)`); err != nil {
		return 0, err
	}
	var dbSize uint64
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM audit_leaves`).Scan(&dbSize); err != nil {
		return 0, err
	}
	if dbSize != l.rng.End() {
		if err := l.reload(ctx, tx); err != nil {
			return 0, err
		}
	}
	work := l.rf.NewEmptyRange(0)
	if err := work.AppendRange(l.rng, nil); err != nil {
		return 0, err
	}
	idx := work.End()
	type node struct {
		id compact.NodeID
		h  []byte
	}
	var nodes []node
	if err := work.Append(leaf, func(id compact.NodeID, h []byte) {
		nodes = append(nodes, node{id, append([]byte(nil), h...)})
	}); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO audit_leaves(idx, ts, entry, entry_raw, leaf_hash) VALUES ($1,$2,$3,$4,$5)`,
		int64(idx), e.Time, raw, raw, leaf); err != nil {
		return 0, err
	}
	for _, n := range nodes {
		if _, err := tx.Exec(ctx, `INSERT INTO audit_nodes(level, idx, hash) VALUES ($1,$2,$3)`, int(n.id.Level), int64(n.id.Index), n.h); err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	l.rng = work
	l.dirty = true
	if l.OnAppend != nil {
		l.OnAppend(idx, e)
	}
	return idx, nil
}

// Record is Append that logs rather than returns failures, for call sites
// where the primary operation has already happened.
func (l *Log) Record(ctx context.Context, e Entry) {
	if _, err := l.Append(ctx, e); err != nil {
		fmt.Printf("audit: append failed: %v\n", err)
	}
}

// root returns the current size and root hash.
func (l *Log) root() (uint64, []byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.rng.End() == 0 {
		return 0, l.hasher.EmptyRoot(), nil
	}
	h, err := l.rng.GetRootHash(nil)
	return l.rng.End(), h, err
}

// SignHead signs and stores a checkpoint for the current tree if it changed.
func (l *Log) SignHead(ctx context.Context) (*TreeHead, error) {
	size, root, err := l.root()
	if err != nil {
		return nil, err
	}
	var exists bool
	if err := l.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM audit_tree_heads WHERE size=$1)`, int64(size)).Scan(&exists); err != nil {
		return nil, err
	}
	if exists {
		return l.LatestHead(ctx)
	}
	ts := time.Now().UTC().Truncate(time.Millisecond)
	sig, err := l.signer.Sign(CheckpointBody(size, root, ts))
	if err != nil {
		return nil, err
	}
	if _, err := l.db.Exec(ctx, `INSERT INTO audit_tree_heads(size, root_hash, ts, signature) VALUES ($1,$2,$3,$4) ON CONFLICT (size) DO NOTHING`,
		int64(size), root, ts, sig); err != nil {
		return nil, err
	}
	return l.LatestHead(ctx)
}

// RunSigner periodically signs new tree heads.
func (l *Log) RunSigner(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			l.mu.Lock()
			d := l.dirty
			l.dirty = false
			l.mu.Unlock()
			if d {
				if _, err := l.SignHead(ctx); err != nil {
					fmt.Printf("audit: sign head: %v\n", err)
				}
			}
		}
	}
}

func (l *Log) LatestHead(ctx context.Context) (*TreeHead, error) {
	th := &TreeHead{PublicKey: l.signer.PublicKey(), Algorithm: l.signer.Algorithm()}
	var size int64
	err := l.db.QueryRow(ctx, `SELECT size, root_hash, ts, signature FROM audit_tree_heads ORDER BY size DESC LIMIT 1`).
		Scan(&size, &th.RootHash, &th.Time, &th.Signature)
	if errors.Is(err, pgx.ErrNoRows) {
		return l.SignHead(ctx)
	}
	if err != nil {
		return nil, err
	}
	th.Size = uint64(size)
	th.Time = th.Time.UTC()
	return th, nil
}

func (l *Log) fetchNodes(ctx context.Context, n proof.Nodes) ([][]byte, error) {
	hashes := make([][]byte, len(n.IDs))
	for i, id := range n.IDs {
		if err := l.db.QueryRow(ctx, `SELECT hash FROM audit_nodes WHERE level=$1 AND idx=$2`, int(id.Level), int64(id.Index)).Scan(&hashes[i]); err != nil {
			return nil, fmt.Errorf("audit: node %d/%d: %w", id.Level, id.Index, err)
		}
	}
	return n.Rehash(hashes, l.hasher.HashChildren)
}

// LeafWithProof is an entry together with its inclusion proof.
type LeafWithProof struct {
	Index    uint64          `json:"index"`
	TreeSize uint64          `json:"tree_size"`
	Entry    json.RawMessage `json:"entry"`
	LeafHash []byte          `json:"leaf_hash"`
	Proof    [][]byte        `json:"proof"`
}

func (l *Log) InclusionProof(ctx context.Context, index, size uint64) (*LeafWithProof, error) {
	if index >= size {
		return nil, fmt.Errorf("audit: index %d outside tree of size %d", index, size)
	}
	var raw, lh []byte
	if err := l.db.QueryRow(ctx, `SELECT entry_raw, leaf_hash FROM audit_leaves WHERE idx=$1`, int64(index)).Scan(&raw, &lh); err != nil {
		return nil, err
	}
	nodes, err := proof.Inclusion(index, size)
	if err != nil {
		return nil, err
	}
	p, err := l.fetchNodes(ctx, nodes)
	if err != nil {
		return nil, err
	}
	return &LeafWithProof{Index: index, TreeSize: size, Entry: raw, LeafHash: lh, Proof: p}, nil
}

func (l *Log) ConsistencyProof(ctx context.Context, size1, size2 uint64) ([][]byte, error) {
	nodes, err := proof.Consistency(size1, size2)
	if err != nil {
		return nil, err
	}
	return l.fetchNodes(ctx, nodes)
}

// Entries returns a page of raw entries starting at index from.
func (l *Log) Entries(ctx context.Context, from uint64, limit int) ([]json.RawMessage, error) {
	rows, err := l.db.Query(ctx, `SELECT entry_raw FROM audit_leaves WHERE idx >= $1 ORDER BY idx LIMIT $2`, int64(from), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []json.RawMessage
	for rows.Next() {
		var b []byte
		if err := rows.Scan(&b); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// VerifyHead checks a checkpoint signature.
func VerifyHead(v cryptoprov.Verifier, th *TreeHead) error {
	return v.Verify(th.PublicKey, CheckpointBody(th.Size, th.RootHash, th.Time), th.Signature)
}

// VerifyInclusion checks an inclusion proof against a root hash.
func VerifyInclusion(p *LeafWithProof, root []byte) error {
	h := rfc6962.New(crypto.SHA256)
	if got := h.HashLeaf(p.Entry); string(got) != string(p.LeafHash) {
		return errors.New("audit: leaf hash does not match entry")
	}
	return proof.VerifyInclusion(h, p.Index, p.TreeSize, p.LeafHash, p.Proof, root)
}

// VerifyConsistency checks that tree size2 is an append-only extension of size1.
func VerifyConsistency(size1, size2 uint64, p [][]byte, root1, root2 []byte) error {
	return proof.VerifyConsistency(rfc6962.New(crypto.SHA256), size1, size2, p, root1, root2)
}

func canonicalJSON(v any) ([]byte, error) {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return []byte(strings.TrimSuffix(b.String(), "\n")), nil
}

// ParseIndex is a helper for HTTP handlers.
func ParseIndex(s string) (uint64, error) { return strconv.ParseUint(s, 10, 64) }
