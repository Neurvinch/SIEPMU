package guard

import (
	"bytes"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/Neurvinch/SIEPMU/server/internal/cryptoprov"
)

func TestFilter(t *testing.T) {
	cfg := FilterConfig{MaxSize: 1 << 20, AllowedTypes: []string{"text/plain", "application/pdf"}, DirtyWords: []string{"NOFORN", "codeword-zulu"}}
	if r := Inspect(cfg, "sitrep.txt", "text/plain", []byte("Routine logistics summary.\n")); r.Blocked {
		t.Fatalf("clean text blocked: %+v", r)
	}
	for name, c := range map[string]struct {
		fn, ct string
		body   []byte
	}{
		"dirty word": {"a.txt", "text/plain", []byte("this is Codeword-ZULU material")},
		"executable": {"a.txt", "text/plain", append([]byte{0x7f, 'E', 'L', 'F'}, make([]byte, 64)...)},
		"type spoof": {"a.txt", "text/plain", []byte("%PDF-1.7\n/JavaScript")},
		"path":       {"../a.txt", "text/plain", []byte("ok")},
		"pdf active": {"a.pdf", "application/pdf", []byte("%PDF-1.7\n1 0 obj << /OpenAction 2 0 R >>")},
		"empty":      {"a.txt", "text/plain", nil},
	} {
		if r := Inspect(cfg, c.fn, c.ct, c.body); !r.Blocked {
			t.Errorf("%s: not blocked: %+v", name, r)
		}
	}
}

func TestDiodeRoundTrip(t *testing.T) {
	p := cryptoprov.NewNIST()
	signer, _, _ := p.NewSigner(nil)
	pub, priv, _ := p.KEM().GenerateKeyPair()
	content := make([]byte, 300_000)
	rand.Read(content)
	meta := Meta{ID: "r1", Filename: "x.bin", Size: int64(len(content)), SHA384: p.Hash384(content), Classification: 2}
	bundle, err := Seal(p, signer, pub, meta, content)
	if err != nil {
		t.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	pc.(*net.UDPConn).SetReadBuffer(8 << 20)
	got := make(chan []byte, 1)
	rc := &Receiver{Deliver: func(b []byte) { got <- b }}
	go rc.Listen(pc)
	if err := Send(pc.LocalAddr().String(), bundle, 3); err != nil {
		t.Fatal(err)
	}
	select {
	case b := <-got:
		m, c, err := Open(p, signer.PublicKey(), priv, b)
		if err != nil || !bytes.Equal(c, content) || m.ID != "r1" {
			t.Fatalf("open: %v", err)
		}
		b[len(b)/2] ^= 1
		if _, _, err := Open(p, signer.PublicKey(), priv, b); err == nil {
			t.Fatal("tampered bundle accepted")
		}
		other, _, _ := p.NewSigner(nil)
		b[len(b)/2] ^= 1
		if _, _, err := Open(p, other.PublicKey(), priv, b); err == nil {
			t.Fatal("bundle from untrusted sender accepted")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("transfer not delivered")
	}
}
