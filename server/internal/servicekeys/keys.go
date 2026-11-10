// Package servicekeys stores long-lived service signing seeds sealed under
// an HSM-resident master KEK. The plaintext seed exists only in process
// memory; the database holds ciphertext that only the HSM can unwrap.
package servicekeys

import (
	"context"
	"crypto/rand"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/Neurvinch/SIEPMU/server/internal/cryptoprov"
	"github.com/Neurvinch/SIEPMU/server/internal/store"
)

// MasterKEK is the HSM key that seals service seeds.
const MasterKEK = "kek-service-master"

// Seed returns the named seed, creating and sealing a new one on first use.
func Seed(ctx context.Context, db *store.Store, kms cryptoprov.KMS, name, algorithm string, size int, publicKey func(seed []byte) []byte) ([]byte, error) {
	var sealed []byte
	err := db.QueryRow(ctx, `SELECT sealed_seed FROM service_keys WHERE name=$1`, name).Scan(&sealed)
	if err == nil {
		return kms.Unwrap(MasterKEK, sealed, []byte("service-key:"+name))
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	seed := make([]byte, size)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	sealed, err = kms.Wrap(MasterKEK, seed, []byte("service-key:"+name))
	if err != nil {
		return nil, err
	}
	tag, err := db.Exec(ctx, `INSERT INTO service_keys(name, algorithm, public_key, sealed_seed) VALUES ($1,$2,$3,$4) ON CONFLICT (name) DO NOTHING`,
		name, algorithm, publicKey(seed), sealed)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 { // another replica won the race
		return Seed(ctx, db, kms, name, algorithm, size, publicKey)
	}
	return seed, nil
}

// HybridSigner loads a composite ML-DSA-65+Ed25519 service signer.
func HybridSigner(ctx context.Context, db *store.Store, kms cryptoprov.KMS, p cryptoprov.Provider, name string) (cryptoprov.Signer, error) {
	seed, err := Seed(ctx, db, kms, name, cryptoprov.HybridSigAlg, cryptoprov.HybridSeedSize, func(s []byte) []byte {
		sg, _, _ := p.NewSigner(s)
		return sg.PublicKey()
	})
	if err != nil {
		return nil, err
	}
	s, _, err := p.NewSigner(seed)
	return s, err
}

// PublicKey returns the stored public key of a named service key.
func PublicKey(ctx context.Context, db *store.Store, name string) ([]byte, error) {
	var pk []byte
	err := db.QueryRow(ctx, `SELECT public_key FROM service_keys WHERE name=$1`, name).Scan(&pk)
	return pk, err
}
