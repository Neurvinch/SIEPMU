// Package cryptoprov is the single cryptographic abstraction used by every
// SIEPMU-SX service. Services depend only on the interfaces in this file;
// the concrete algorithms live behind a Provider implementation so that a
// SAG-approved module can replace the NIST public-algorithm provider without
// any change to service code.
package cryptoprov

import (
	"crypto"
	"errors"
)

// KEM is a key-encapsulation mechanism (hybrid ML-KEM-768 + X25519 in the
// NIST provider).
type KEM interface {
	Name() string
	GenerateKeyPair() (pub, priv []byte, err error)
	Encapsulate(pub []byte) (ciphertext, sharedSecret []byte, err error)
	Decapsulate(priv, ciphertext []byte) (sharedSecret []byte, err error)
}

// Signer produces signatures that are verifiable with the matching Verifier.
type Signer interface {
	Algorithm() string
	PublicKey() []byte
	Sign(message []byte) ([]byte, error)
}

// Verifier checks signatures for a given algorithm.
type Verifier interface {
	Algorithm() string
	Verify(publicKey, message, signature []byte) error
}

// AEAD is authenticated encryption with associated data.
type AEAD interface {
	Name() string
	KeySize() int
	Seal(key, plaintext, aad []byte) ([]byte, error) // returns nonce||ciphertext
	Open(key, sealed, aad []byte) ([]byte, error)
}

// KMS wraps and unwraps data-encryption keys under key-encryption keys that
// never leave the HSM.
type KMS interface {
	// CreateKEK creates a new non-extractable key-encryption key with the
	// given label and returns its identifier.
	CreateKEK(label string) (string, error)
	// Wrap encrypts a DEK under the KEK identified by kekID.
	Wrap(kekID string, dek, aad []byte) ([]byte, error)
	// Unwrap decrypts a DEK previously produced by Wrap.
	Unwrap(kekID string, wrapped, aad []byte) ([]byte, error)
	// DestroyKEK permanently deletes a KEK; every DEK wrapped under it becomes
	// unrecoverable (cryptographic erasure).
	DestroyKEK(kekID string) error
	// Signer returns an HSM-resident signing key (used by the internal CA).
	Signer(label string) (crypto.Signer, error)
	// CreateSigner generates an HSM-resident ECDSA P-384 signing key.
	CreateSigner(label string) (crypto.Signer, error)
	Close() error
}

// Provider bundles every primitive a service may need.
type Provider interface {
	Name() string
	KEM() KEM
	AEAD() AEAD
	// NewSigner loads (or generates, when seed is nil) a signing key.
	NewSigner(seed []byte) (Signer, []byte, error)
	Verifier() Verifier
	Hash384(data []byte) []byte
	Random(n int) ([]byte, error)
}

var (
	ErrBadSignature = errors.New("cryptoprov: signature verification failed")
	ErrDecrypt      = errors.New("cryptoprov: authenticated decryption failed")
)
