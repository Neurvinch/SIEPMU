package cryptoprov

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/kem/xwing"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// NIST is the prototype provider built only on public NIST / IETF algorithms:
//   - KEM:       X-Wing (ML-KEM-768 FIPS 203 + X25519), draft-connolly-cfrg-xwing-kem
//   - Signature: composite ML-DSA-65 (FIPS 204) + Ed25519; both must verify
//   - AEAD:      AES-256-GCM with random 96-bit nonces
//   - Hash:      SHA-384
type NIST struct{}

func NewNIST() *NIST { return &NIST{} }

func (NIST) Name() string     { return "nist-public-v1" }
func (NIST) KEM() KEM         { return xwingKEM{} }
func (NIST) AEAD() AEAD       { return aesGCM{} }
func (NIST) Verifier() Verifier { return hybridVerifier{} }

func (NIST) Hash384(data []byte) []byte {
	h := sha512.Sum384(data)
	return h[:]
}

func (NIST) Random(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

// HybridSeedSize is the seed length of a composite signing key.
const HybridSeedSize = mldsa65.SeedSize + ed25519.SeedSize

// HybridSigAlg names the composite signature algorithm.
const HybridSigAlg = "ML-DSA-65+Ed25519"

// NewSigner returns a composite signer. When seed is nil a fresh seed is
// generated and returned so the caller can persist it (sealed by the KMS).
func (NIST) NewSigner(seed []byte) (Signer, []byte, error) {
	if seed == nil {
		seed = make([]byte, HybridSeedSize)
		if _, err := rand.Read(seed); err != nil {
			return nil, nil, err
		}
	}
	if len(seed) != HybridSeedSize {
		return nil, nil, fmt.Errorf("cryptoprov: signer seed must be %d bytes", HybridSeedSize)
	}
	var ms [mldsa65.SeedSize]byte
	copy(ms[:], seed[:mldsa65.SeedSize])
	mpk, msk := mldsa65.NewKeyFromSeed(&ms)
	esk := ed25519.NewKeyFromSeed(seed[mldsa65.SeedSize:])
	pub := append(mpk.Bytes(), esk.Public().(ed25519.PublicKey)...)
	return &hybridSigner{msk: msk, esk: esk, pub: pub}, seed, nil
}

type hybridSigner struct {
	msk *mldsa65.PrivateKey
	esk ed25519.PrivateKey
	pub []byte
}

// sigContext domain-separates SIEPMU signatures (FIPS 204 context string).
var sigContext = []byte("SIEPMU-SX/v1")

func (s *hybridSigner) Algorithm() string { return HybridSigAlg }
func (s *hybridSigner) PublicKey() []byte { return append([]byte(nil), s.pub...) }

func (s *hybridSigner) Sign(msg []byte) ([]byte, error) {
	sig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(s.msk, msg, sigContext, true, sig); err != nil {
		return nil, err
	}
	return append(sig, ed25519.Sign(s.esk, msg)...), nil
}

type hybridVerifier struct{}

func (hybridVerifier) Algorithm() string { return HybridSigAlg }

func (hybridVerifier) Verify(pub, msg, sig []byte) error {
	if len(pub) != mldsa65.PublicKeySize+ed25519.PublicKeySize ||
		len(sig) != mldsa65.SignatureSize+ed25519.SignatureSize {
		return ErrBadSignature
	}
	var mpk mldsa65.PublicKey
	if err := mpk.UnmarshalBinary(pub[:mldsa65.PublicKeySize]); err != nil {
		return ErrBadSignature
	}
	if !mldsa65.Verify(&mpk, msg, sigContext, sig[:mldsa65.SignatureSize]) {
		return ErrBadSignature
	}
	if !ed25519.Verify(pub[mldsa65.PublicKeySize:], msg, sig[mldsa65.SignatureSize:]) {
		return ErrBadSignature
	}
	return nil
}

type xwingKEM struct{}

func (xwingKEM) Name() string { return "X-Wing(ML-KEM-768+X25519)" }

func (xwingKEM) GenerateKeyPair() ([]byte, []byte, error) {
	sk, pk, err := xwing.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pb := make([]byte, xwing.PublicKeySize)
	sb := make([]byte, xwing.PrivateKeySize)
	pk.Pack(pb)
	sk.Pack(sb)
	return pb, sb, nil
}

func (xwingKEM) Encapsulate(pub []byte) ([]byte, []byte, error) {
	if len(pub) != xwing.PublicKeySize {
		return nil, nil, errors.New("cryptoprov: bad X-Wing public key size")
	}
	seed := make([]byte, xwing.EncapsulationSeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, nil, err
	}
	ss, ct, err := xwing.Encapsulate(pub, seed)
	if err != nil {
		return nil, nil, err
	}
	return ct, ss, nil
}

func (xwingKEM) Decapsulate(priv, ct []byte) ([]byte, error) {
	if len(priv) != xwing.PrivateKeySize || len(ct) != xwing.CiphertextSize {
		return nil, errors.New("cryptoprov: bad X-Wing key or ciphertext size")
	}
	return xwing.Decapsulate(ct, priv), nil
}

type aesGCM struct{}

func (aesGCM) Name() string { return "AES-256-GCM" }
func (aesGCM) KeySize() int { return 32 }

func (aesGCM) Seal(key, pt, aad []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("cryptoprov: AES-256-GCM needs a 32-byte key")
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return g.Seal(nonce, nonce, pt, aad), nil
}

func (aesGCM) Open(key, sealed, aad []byte) ([]byte, error) {
	if len(key) != 32 {
		return nil, errors.New("cryptoprov: AES-256-GCM needs a 32-byte key")
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	if len(sealed) < g.NonceSize()+g.Overhead() {
		return nil, ErrDecrypt
	}
	pt, err := g.Open(nil, sealed[:g.NonceSize()], sealed[g.NonceSize():], aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}
