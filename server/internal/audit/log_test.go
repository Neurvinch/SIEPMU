package audit

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/Neurvinch/SIEPMU/server/internal/cryptoprov"
	"github.com/Neurvinch/SIEPMU/server/internal/store"
)

func TestLogProofs(t *testing.T) {
	dsn := os.Getenv("SIEPMU_TEST_DSN")
	if dsn == "" {
		t.Skip("SIEPMU_TEST_DSN not set")
	}
	ctx := context.Background()
	db, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	db.Exec(ctx, `TRUNCATE audit_leaves, audit_nodes, audit_tree_heads`)
	p := cryptoprov.NewNIST()
	signer, _, _ := p.NewSigner(nil)
	l, err := New(ctx, db, signer)
	if err != nil {
		t.Fatal(err)
	}
	heads := map[uint64]*TreeHead{}
	for i := 0; i < 37; i++ {
		if _, err := l.Append(ctx, Entry{Actor: "test", Action: fmt.Sprintf("op-%d", i), Outcome: "success"}); err != nil {
			t.Fatal(err)
		}
		if i == 4 || i == 15 || i == 36 {
			th, err := l.SignHead(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyHead(p.Verifier(), th); err != nil {
				t.Fatal(err)
			}
			heads[th.Size] = th
		}
	}
	// Rebuild from the database to prove persistence of the right edge.
	l2, err := New(ctx, db, signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l2.Append(ctx, Entry{Actor: "test", Action: "after-reload", Outcome: "success"}); err != nil {
		t.Fatal(err)
	}
	th, _ := l2.SignHead(ctx)
	heads[th.Size] = th
	for _, size := range []uint64{5, 16, 37, 38} {
		h := heads[size]
		for idx := uint64(0); idx < size; idx++ {
			lp, err := l2.InclusionProof(ctx, idx, size)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyInclusion(lp, h.RootHash); err != nil {
				t.Fatalf("inclusion %d/%d: %v", idx, size, err)
			}
		}
	}
	for _, pair := range [][2]uint64{{5, 16}, {16, 37}, {5, 38}, {37, 38}} {
		cp, err := l2.ConsistencyProof(ctx, pair[0], pair[1])
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyConsistency(pair[0], pair[1], cp, heads[pair[0]].RootHash, heads[pair[1]].RootHash); err != nil {
			t.Fatalf("consistency %v: %v", pair, err)
		}
	}
	// Tampering with a stored entry must break verification.
	db.Exec(ctx, `UPDATE audit_leaves SET entry_raw = convert_to('{"forged":true}','UTF8') WHERE idx=3`)
	lp, _ := l2.InclusionProof(ctx, 3, 38)
	if VerifyInclusion(lp, heads[38].RootHash) == nil {
		t.Fatal("tampered entry verified")
	}
}
