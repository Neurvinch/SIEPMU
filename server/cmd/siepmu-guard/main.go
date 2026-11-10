// siepmu-guard is the RED-side receiver of the cross-domain guard. It
// listens on the receive side of the one-way link, never transmits, and
// accepts only bundles signed by the BLACK guard and encrypted to its key.
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Neurvinch/SIEPMU/server/internal/cryptoprov"
	"github.com/Neurvinch/SIEPMU/server/internal/guard"
)

func readB64(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}
	out, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		log.Fatalf("%s: %v", path, err)
	}
	return out
}

func main() {
	listen := flag.String("listen", ":9700", "UDP address on the diode receive side")
	keyFile := flag.String("key", "guard-kem.key", "X-Wing private key (siepmuctl keygen --type kem)")
	sender := flag.String("sender-pubkey", "", "BLACK guard signing public key, base64 (siepmuctl guard-pubkey)")
	inbox := flag.String("inbox", "inbox", "directory for released content")
	flag.Parse()
	p := cryptoprov.NewNIST()
	priv := readB64(*keyFile)
	senderPub, err := base64.StdEncoding.DecodeString(*sender)
	if err != nil || len(senderPub) == 0 {
		log.Fatal("--sender-pubkey is required")
	}
	if err := os.MkdirAll(*inbox, 0o700); err != nil {
		log.Fatal(err)
	}
	journal, err := os.OpenFile(filepath.Join(*inbox, "journal.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		log.Fatal(err)
	}
	pc, err := net.ListenPacket("udp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	if uc, ok := pc.(*net.UDPConn); ok {
		uc.SetReadBuffer(16 << 20)
	}
	log.Printf("RED guard receiving on %s (receive-only)", *listen)
	rc := &guard.Receiver{Deliver: func(bundle []byte) {
		sum := sha256.Sum256(bundle)
		meta, content, err := guard.Open(p, senderPub, priv, bundle)
		rec := map[string]any{"time": time.Now().UTC(), "bundle_sha256": hex.EncodeToString(sum[:])}
		if err != nil {
			rec["result"], rec["error"] = "rejected", err.Error()
			log.Printf("rejected bundle: %v", err)
		} else {
			dir := filepath.Join(*inbox, meta.ID)
			os.MkdirAll(dir, 0o700)
			name := filepath.Base(meta.Filename)
			if err := os.WriteFile(filepath.Join(dir, name), content, 0o600); err != nil {
				log.Printf("write: %v", err)
				return
			}
			mj, _ := json.MarshalIndent(meta, "", "  ")
			os.WriteFile(filepath.Join(dir, "release.json"), mj, 0o600)
			rec["result"], rec["release"], rec["filename"], rec["classification"] = "accepted", meta.ID, name, meta.Classification
			log.Printf("accepted release %s (%s, %d bytes, released by %d officers)", meta.ID, name, len(content), len(meta.ReleasedBy))
		}
		b, _ := json.Marshal(rec)
		journal.Write(append(b, '\n'))
		journal.Sync()
	}}
	log.Fatal(rc.Listen(pc))
}
