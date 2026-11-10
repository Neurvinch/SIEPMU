package bridge

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strings"
	"time"
	"unicode/utf8"
)

// SBD receives Iridium Short Burst Data mobile-originated messages over the
// DirectIP protocol (the gateway opens one TCP connection per message):
//
//	protocol revision (1) | overall length (u16) | information elements...
//	IE = id (u8) | length (u16) | content
//	0x01 MO header: CDR ref u32, IMEI [15], status u8, MOMSN u16, MTMSN u16, time u32
//	0x02 MO payload, 0x03 MO location
type SBD struct {
	Listen string
	Class  int
}

func (s *SBD) Name() string { return "sbd" }

type sbdMO struct {
	IMEI    string
	Status  byte
	MOMSN   uint16
	Time    time.Time
	Payload []byte
}

func parseDirectIP(msg []byte) (*sbdMO, error) {
	if len(msg) < 3 || msg[0] != 1 {
		return nil, errors.New("sbd: unsupported DirectIP protocol revision")
	}
	total := int(binary.BigEndian.Uint16(msg[1:]))
	if total != len(msg)-3 {
		return nil, errors.New("sbd: overall length mismatch")
	}
	mo := &sbdMO{}
	hdr := false
	for b := msg[3:]; len(b) > 0; {
		if len(b) < 3 {
			return nil, errors.New("sbd: truncated information element")
		}
		id, n := b[0], int(binary.BigEndian.Uint16(b[1:]))
		if n > len(b)-3 {
			return nil, errors.New("sbd: truncated information element")
		}
		c := b[3 : 3+n]
		switch id {
		case 0x01:
			if n != 28 {
				return nil, errors.New("sbd: MO header must be 28 bytes")
			}
			mo.IMEI = string(c[4:19])
			mo.Status = c[19]
			mo.MOMSN = binary.BigEndian.Uint16(c[20:])
			mo.Time = time.Unix(int64(binary.BigEndian.Uint32(c[24:])), 0).UTC()
			hdr = true
		case 0x02:
			mo.Payload = append([]byte(nil), c...)
		}
		b = b[3+n:]
	}
	if !hdr {
		return nil, errors.New("sbd: missing MO header")
	}
	return mo, nil
}

func (s *SBD) Run(ctx context.Context, emit func(Envelope)) error {
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", s.Listen)
	if err != nil {
		return err
	}
	context.AfterFunc(ctx, func() { ln.Close() })
	for {
		conn, err := ln.Accept()
		if err != nil {
			return ctx.Err()
		}
		go func() {
			defer conn.Close()
			conn.SetReadDeadline(time.Now().Add(30 * time.Second))
			msg, err := io.ReadAll(io.LimitReader(conn, 4096))
			if err != nil && len(msg) == 0 {
				return
			}
			mo, err := parseDirectIP(msg)
			if err != nil || mo.Status > 2 || len(mo.Payload) == 0 { // 0..2 = transfer OK
				return
			}
			body := string(mo.Payload)
			if !utf8.Valid(mo.Payload) {
				body = "HEX:" + strings.ToUpper(hex.EncodeToString(mo.Payload))
			}
			emit(Envelope{Adapter: "sbd", Origin: mo.IMEI, Destination: mo.IMEI, Precedence: "ROUTINE", Classification: s.Class, Body: body, Raw: msg})
		}()
	}
}

func (s *SBD) Send(string, string) error {
	return errors.New("sbd: mobile-terminated DirectIP is not implemented; satellite terminals are receive-only on this bridge")
}
