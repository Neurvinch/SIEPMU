package cryptoprov

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"

	"github.com/eclipse-keypont/crypto11"
)

// PKCS11KMS implements KMS on any PKCS#11 v2.20+ token (SoftHSM2 in
// development, a FIPS 140-3 HSM in production). Key-encryption keys are
// generated inside the token as CKA_SENSITIVE / non-extractable AES-256 keys
// and every wrap/unwrap is an AES-256-GCM operation executed by the token.
type PKCS11KMS struct {
	ctx *crypto11.Context
	mu  sync.Mutex
	kek map[string]*crypto11.SecretKey
}

// PKCS11Config selects the token.
type PKCS11Config struct {
	ModulePath string `yaml:"module_path"`
	TokenLabel string `yaml:"token_label"`
	PIN        string `yaml:"pin"`
}

func NewPKCS11KMS(cfg PKCS11Config) (*PKCS11KMS, error) {
	ctx, err := crypto11.Configure(&crypto11.Config{
		Path:        cfg.ModulePath,
		TokenLabel:  cfg.TokenLabel,
		Pin:         cfg.PIN,
		GCMIVLength: 12,
	})
	if err != nil {
		return nil, fmt.Errorf("kms: open PKCS#11 token %q: %w", cfg.TokenLabel, err)
	}
	return &PKCS11KMS{ctx: ctx, kek: map[string]*crypto11.SecretKey{}}, nil
}

func (k *PKCS11KMS) find(id string) (*crypto11.SecretKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if key, ok := k.kek[id]; ok {
		return key, nil
	}
	key, err := k.ctx.FindKey([]byte(id), nil)
	if err != nil {
		return nil, err
	}
	if key == nil {
		return nil, fmt.Errorf("kms: key %q not found in HSM", id)
	}
	k.kek[id] = key
	return key, nil
}

func (k *PKCS11KMS) CreateKEK(label string) (string, error) {
	idb := make([]byte, 16)
	if _, err := rand.Read(idb); err != nil {
		return "", err
	}
	id := fmt.Sprintf("kek-%x", idb)
	key, err := k.ctx.GenerateSecretKeyWithLabel([]byte(id), []byte(label), 256, crypto11.CipherAES)
	if err != nil {
		return "", fmt.Errorf("kms: generate KEK: %w", err)
	}
	k.mu.Lock()
	k.kek[id] = key
	k.mu.Unlock()
	return id, nil
}

// EnsureKEK returns the KEK with a fixed id, creating it on first use.
func (k *PKCS11KMS) EnsureKEK(id string) error {
	if _, err := k.find(id); err == nil {
		return nil
	}
	key, err := k.ctx.GenerateSecretKeyWithLabel([]byte(id), []byte(id), 256, crypto11.CipherAES)
	if err != nil {
		return fmt.Errorf("kms: generate KEK %s: %w", id, err)
	}
	k.mu.Lock()
	k.kek[id] = key
	k.mu.Unlock()
	return nil
}

func (k *PKCS11KMS) Wrap(id string, dek, aad []byte) ([]byte, error) {
	key, err := k.find(id)
	if err != nil {
		return nil, err
	}
	g, err := key.NewGCM()
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return g.Seal(nonce, nonce, dek, aad), nil
}

func (k *PKCS11KMS) Unwrap(id string, wrapped, aad []byte) ([]byte, error) {
	key, err := k.find(id)
	if err != nil {
		return nil, err
	}
	g, err := key.NewGCM()
	if err != nil {
		return nil, err
	}
	if len(wrapped) < g.NonceSize()+g.Overhead() {
		return nil, ErrDecrypt
	}
	pt, err := g.Open(nil, wrapped[:g.NonceSize()], wrapped[g.NonceSize():], aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

func (k *PKCS11KMS) DestroyKEK(id string) error {
	key, err := k.find(id)
	if err != nil {
		return err
	}
	if err := key.Delete(); err != nil {
		return err
	}
	k.mu.Lock()
	delete(k.kek, id)
	k.mu.Unlock()
	return nil
}

func (k *PKCS11KMS) Signer(label string) (crypto.Signer, error) {
	s, err := k.ctx.FindKeyPair(nil, []byte(label))
	if err != nil {
		return nil, err
	}
	if s == nil {
		return nil, errors.New("kms: signing key " + label + " not found")
	}
	return s, nil
}

func (k *PKCS11KMS) CreateSigner(label string) (crypto.Signer, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	return k.ctx.GenerateECDSAKeyPairWithLabel(id, []byte(label), elliptic.P384())
}

func (k *PKCS11KMS) Close() error { return k.ctx.Close() }
