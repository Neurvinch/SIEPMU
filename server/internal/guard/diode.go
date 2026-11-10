// Package guard is the RED/BLACK cross-domain guard. Content leaves the
// BLACK mesh only after (1) an automated content filter, (2) release by a
// quorum of release officers who are not the submitter, and (3) transfer
// over a one-way link. The link protocol is UDP with no return channel of
// any kind (it works across a hardware data diode): the sender repeats each
// frame, and the receiver accepts a transfer only if the reassembled bundle
// carries a valid composite ML-DSA-65+Ed25519 signature from the BLACK
// guard and decrypts under the receiver's X-Wing key.
package guard

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/Neurvinch/SIEPMU/server/internal/cryptoprov"
)

var magic = [4]byte{'S', 'X', 'D', 'D'}

const (
	frameHeader  = 4 + 16 + 4 + 4
	framePayload = 1200
	// MaxBundle bounds receiver memory per transfer.
	MaxBundle = 64 << 20
)

// Meta travels with the content and is bound into the AEAD and signature.
type Meta struct {
	ID             string    `json:"id"`
	Filename       string    `json:"filename"`
	ContentType    string    `json:"content_type"`
	Classification int       `json:"classification"`
	Size           int64     `json:"size"`
	SHA384         []byte    `json:"sha384"`
	SubmittedBy    string    `json:"submitted_by"`
	ReleasedBy     []string  `json:"released_by"`
	ReleasedAt     time.Time `json:"released_at"`
}

// Seal builds the signed, encrypted bundle for the RED-side receiver.
func Seal(p cryptoprov.Provider, signer cryptoprov.Signer, receiverKEMPub []byte, meta Meta, content []byte) ([]byte, error) {
	mj, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	ct, ss, err := p.KEM().Encapsulate(receiverKEMPub)
	if err != nil {
		return nil, err
	}
	sealed, err := p.AEAD().Seal(ss, content, mj)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	for _, part := range [][]byte{mj, ct, sealed} {
		binary.Write(&b, binary.BigEndian, uint32(len(part)))
		b.Write(part)
	}
	sig, err := signer.Sign(b.Bytes())
	if err != nil {
		return nil, err
	}
	binary.Write(&b, binary.BigEndian, uint32(len(sig)))
	b.Write(sig)
	return b.Bytes(), nil
}

// Open verifies and decrypts a bundle on the RED side.
func Open(p cryptoprov.Provider, senderPub, kemPriv, bundle []byte) (*Meta, []byte, error) {
	parts := make([][]byte, 0, 4)
	rest := bundle
	offsets := []int{}
	for i := 0; i < 4; i++ {
		if len(rest) < 4 {
			return nil, nil, errors.New("guard: truncated bundle")
		}
		n := int(binary.BigEndian.Uint32(rest))
		if n > len(rest)-4 {
			return nil, nil, errors.New("guard: truncated bundle")
		}
		parts = append(parts, rest[4:4+n])
		rest = rest[4+n:]
		offsets = append(offsets, len(bundle)-len(rest))
	}
	if len(rest) != 0 {
		return nil, nil, errors.New("guard: trailing bytes in bundle")
	}
	if err := p.Verifier().Verify(senderPub, bundle[:offsets[2]], parts[3]); err != nil {
		return nil, nil, fmt.Errorf("guard: bundle signature: %w", err)
	}
	var meta Meta
	if err := json.Unmarshal(parts[0], &meta); err != nil {
		return nil, nil, err
	}
	ss, err := p.KEM().Decapsulate(kemPriv, parts[1])
	if err != nil {
		return nil, nil, err
	}
	content, err := p.AEAD().Open(ss, parts[2], parts[0])
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(p.Hash384(content), meta.SHA384) || int64(len(content)) != meta.Size {
		return nil, nil, errors.New("guard: content does not match released hash")
	}
	return &meta, content, nil
}

// Send transmits a bundle over the one-way link. Nothing is ever read from
// the socket. Each frame is sent `repeat` times in interleaved passes so a
// burst loss does not remove every copy of a frame.
func Send(addr string, bundle []byte, repeat int) error {
	if len(bundle) > MaxBundle {
		return errors.New("guard: bundle too large for diode transfer")
	}
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	var tid [16]byte
	if _, err := rand.Read(tid[:]); err != nil {
		return err
	}
	total := (len(bundle) + framePayload - 1) / framePayload
	buf := make([]byte, frameHeader+framePayload)
	for pass := 0; pass < repeat; pass++ {
		for i := 0; i < total; i++ {
			chunk := bundle[i*framePayload : min((i+1)*framePayload, len(bundle))]
			copy(buf, magic[:])
			copy(buf[4:], tid[:])
			binary.BigEndian.PutUint32(buf[20:], uint32(i))
			binary.BigEndian.PutUint32(buf[24:], uint32(total))
			n := copy(buf[frameHeader:], chunk)
			if _, err := conn.Write(buf[:frameHeader+n]); err != nil {
				return err
			}
			if i%64 == 63 {
				time.Sleep(2 * time.Millisecond) // pace to avoid receiver buffer overrun
			}
		}
	}
	return nil
}

type transfer struct {
	frames [][]byte
	have   int
	seen   time.Time
}

// Receiver reassembles transfers and hands complete bundles to Deliver.
type Receiver struct {
	Deliver func(bundle []byte)
	mu      sync.Mutex
	active  map[[16]byte]*transfer
	done    map[[16]byte]time.Time
}

// Listen receives until the connection is closed. It never writes.
func (r *Receiver) Listen(conn net.PacketConn) error {
	r.active = map[[16]byte]*transfer{}
	r.done = map[[16]byte]time.Time{}
	buf := make([]byte, 2048)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			return err
		}
		if n < frameHeader || !bytes.Equal(buf[:4], magic[:]) {
			continue
		}
		var tid [16]byte
		copy(tid[:], buf[4:20])
		seq := binary.BigEndian.Uint32(buf[20:])
		total := binary.BigEndian.Uint32(buf[24:])
		if total == 0 || seq >= total || int(total) > MaxBundle/framePayload+1 {
			continue
		}
		r.mu.Lock()
		r.gc()
		if _, dup := r.done[tid]; dup {
			r.mu.Unlock()
			continue
		}
		t := r.active[tid]
		if t == nil {
			if len(r.active) >= 32 { // bound memory against junk transfers
				r.mu.Unlock()
				continue
			}
			t = &transfer{frames: make([][]byte, total)}
			r.active[tid] = t
		}
		if int(total) != len(t.frames) {
			r.mu.Unlock()
			continue
		}
		t.seen = time.Now()
		if t.frames[seq] == nil {
			t.frames[seq] = append([]byte(nil), buf[frameHeader:n]...)
			t.have++
		}
		var bundle []byte
		if t.have == len(t.frames) {
			bundle = bytes.Join(t.frames, nil)
			delete(r.active, tid)
			r.done[tid] = time.Now()
		}
		r.mu.Unlock()
		if bundle != nil {
			r.Deliver(bundle)
		}
	}
}

func (r *Receiver) gc() {
	now := time.Now()
	for k, t := range r.active {
		if now.Sub(t.seen) > 2*time.Minute {
			delete(r.active, k)
		}
	}
	for k, t := range r.done {
		if now.Sub(t) > 10*time.Minute {
			delete(r.done, k)
		}
	}
}
