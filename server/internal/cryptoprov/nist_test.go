package cryptoprov

import (
	"bytes"
	"os"
	"testing"
)

func TestHybridSignature(t *testing.T) {
	p := NewNIST()
	s, seed, err := p.NewSigner(nil)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("tree head 42")
	sig, err := s.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Verifier().Verify(s.PublicKey(), msg, sig); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	sig[10] ^= 1
	if p.Verifier().Verify(s.PublicKey(), msg, sig) == nil {
		t.Fatal("tampered ML-DSA half accepted")
	}
	sig[10] ^= 1
	sig[len(sig)-1] ^= 1
	if p.Verifier().Verify(s.PublicKey(), msg, sig) == nil {
		t.Fatal("tampered Ed25519 half accepted")
	}
	s2, _, _ := p.NewSigner(seed)
	if !bytes.Equal(s2.PublicKey(), s.PublicKey()) {
		t.Fatal("seed did not reproduce key")
	}
}

func TestXWing(t *testing.T) {
	k := NewNIST().KEM()
	pub, priv, err := k.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ct, ss1, err := k.Encapsulate(pub)
	if err != nil {
		t.Fatal(err)
	}
	ss2, err := k.Decapsulate(priv, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ss1, ss2) {
		t.Fatal("shared secrets differ")
	}
}

func TestAESGCM(t *testing.T) {
	a := NewNIST().AEAD()
	key, _ := NewNIST().Random(32)
	ct, err := a.Seal(key, []byte("hello"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Open(key, ct, []byte("other")); err == nil {
		t.Fatal("wrong AAD accepted")
	}
	pt, err := a.Open(key, ct, []byte("aad"))
	if err != nil || string(pt) != "hello" {
		t.Fatal("round trip failed")
	}
}

// TestPKCS11KMS runs against a real token when SIEPMU_TEST_PKCS11 is set to
// the module path (e.g. /usr/lib/softhsm/libsofthsm2.so).
func TestPKCS11KMS(t *testing.T) {
	mod := os.Getenv("SIEPMU_TEST_PKCS11")
	if mod == "" {
		t.Skip("SIEPMU_TEST_PKCS11 not set")
	}
	k, err := NewPKCS11KMS(PKCS11Config{ModulePath: mod, TokenLabel: os.Getenv("SIEPMU_TEST_TOKEN"), PIN: os.Getenv("SIEPMU_TEST_PIN")})
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	id, err := k.CreateKEK("test")
	if err != nil {
		t.Fatal(err)
	}
	dek := []byte("0123456789abcdef0123456789abcdef")
	w, err := k.Wrap(id, dek, []byte("file-1"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := k.Unwrap(id, w, []byte("file-1"))
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("unwrap: %v", err)
	}
	if _, err := k.Unwrap(id, w, []byte("file-2")); err == nil {
		t.Fatal("unwrap with wrong AAD succeeded")
	}
	if err := k.DestroyKEK(id); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Unwrap(id, w, []byte("file-1")); err == nil {
		t.Fatal("unwrap after crypto-erasure succeeded")
	}
}
