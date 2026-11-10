package bridge

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"testing"
	"time"

	"github.com/Neurvinch/SIEPMU/server/internal/cryptoprov"
)

func TestKISSAX25(t *testing.T) {
	info := []byte{'h', 'i', fend, fesc, '!'}
	f, err := ax25EncodeUI("VU2HQ-1", "VU2ABC-7", info)
	if err != nil {
		t.Fatal(err)
	}
	wire := append([]byte{fend, fend}, kissEncode(f)...) // leading idle FENDs
	got, err := kissRead(bufio.NewReader(bytes.NewReader(wire)))
	if err != nil || !bytes.Equal(got, f) {
		t.Fatalf("kiss round trip: %v", err)
	}
	dst, src, body, err := ax25DecodeUI(got)
	if err != nil || dst != "VU2HQ-1" || src != "VU2ABC-7" || !bytes.Equal(body, info) {
		t.Fatalf("ax25: %s %s %q %v", dst, src, body, err)
	}
	// Frame with one digipeater in the path.
	d, _ := ax25Addr("APRS", false)
	s, _ := ax25Addr("VU2ABC", false)
	r, _ := ax25Addr("WIDE1-1", true)
	fr := append(append(append(append(d, s...), r...), 0x03, 0xF0), []byte("via digi")...)
	if _, src, body, err := ax25DecodeUI(fr); err != nil || src != "VU2ABC" || string(body) != "via digi" {
		t.Fatalf("digipeated frame: %v", err)
	}
}

func TestACP127(t *testing.T) {
	msg := "PAAUZYUW RUHQABC0042 3141200\nP 101200Z NOV 26\nFM 17 SQN GORAKHPUR\nTO HQ CAC PRAYAGRAJ\nINFO AIR HQ\nBT\nRESTRICTED\nSUBJ: FUEL STATE\n1. AVTUR 80 PERCENT.\nBT\n#0042\n"
	e, err := ParseACP127(msg)
	if err != nil {
		t.Fatal(err)
	}
	if e.Precedence != "PRIORITY" || e.Origin != "17 SQN GORAKHPUR" || e.Destination != "HQ CAC PRAYAGRAJ" || e.Classification != 1 || e.Body != "SUBJ: FUEL STATE\n1. AVTUR 80 PERCENT." {
		t.Fatalf("%+v", e)
	}
	out := FormatACP127("RUHQSX", 7, e, time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC))
	e2, err := ParseACP127(out[:len(out)-len("NNNN\r\n")])
	if err != nil || e2.Body != e.Body || e2.Precedence != e.Precedence || e2.Classification != 1 {
		t.Fatalf("format/parse round trip: %v %+v", err, e2)
	}
	if _, err := ParseACP127("garbage\nBT\nhello\nBT\n"); err == nil {
		t.Fatal("malformed message accepted")
	}
}

func TestDirectIP(t *testing.T) {
	hdr := make([]byte, 28)
	binary.BigEndian.PutUint32(hdr, 12345)
	copy(hdr[4:], "300234010753370")
	hdr[19] = 0
	binary.BigEndian.PutUint16(hdr[20:], 54)
	binary.BigEndian.PutUint32(hdr[24:], 1794312000)
	payload := []byte("POSREP 2612N 08322E")
	var ies []byte
	ies = append(ies, 0x01, 0, 28)
	ies = append(ies, hdr...)
	ies = append(ies, 0x02, 0, byte(len(payload)))
	ies = append(ies, payload...)
	msg := append([]byte{1, byte(len(ies) >> 8), byte(len(ies))}, ies...)
	mo, err := parseDirectIP(msg)
	if err != nil || mo.IMEI != "300234010753370" || mo.MOMSN != 54 || string(mo.Payload) != string(payload) {
		t.Fatalf("%+v %v", mo, err)
	}
	if _, err := parseDirectIP(msg[:len(msg)-2]); err == nil {
		t.Fatal("truncated message accepted")
	}
}

func TestSpoolAndSign(t *testing.T) {
	p := cryptoprov.NewNIST()
	s, _, _ := p.NewSigner(nil)
	sp := Spool{Dir: t.TempDir()}
	var clock HLC
	mk := func(prec, body string) Signed {
		sg, err := Sign(s, Envelope{Bridge: "b", Adapter: "ax25", Precedence: prec, HLC: clock.Now(), Body: body})
		if err != nil {
			t.Fatal(err)
		}
		return sg
	}
	a, b, c := mk("ROUTINE", "one"), mk("FLASH", "two"), mk("ROUTINE", "three")
	for _, x := range []Signed{a, b, c, a} {
		if err := sp.Put(x); err != nil {
			t.Fatal(err)
		}
	}
	pend, _ := sp.Pending(10)
	if len(pend) != 3 || pend[0].ID != b.ID || pend[1].ID != a.ID || pend[2].ID != c.ID {
		t.Fatal("spool must dedup and order FLASH first, then by HLC")
	}
	if _, err := Verify(p.Verifier(), s.PublicKey(), a); err != nil {
		t.Fatal(err)
	}
	a.Envelope = append([]byte(nil), a.Envelope...)
	a.Envelope[10] ^= 1
	if _, err := Verify(p.Verifier(), s.PublicKey(), a); err == nil {
		t.Fatal("tampered envelope verified")
	}
	sp.Ack(b.ID)
	if pend, _ = sp.Pending(10); len(pend) != 2 {
		t.Fatal("ack did not remove")
	}
}
