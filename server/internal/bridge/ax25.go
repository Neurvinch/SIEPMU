package bridge

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// KISS framing constants (TNC protocol used by Direwolf, soundmodem and
// hardware HF/VHF packet modems).
const (
	fend  = 0xC0
	fesc  = 0xDB
	tfend = 0xDC
	tfesc = 0xDD
)

func kissEncode(data []byte) []byte {
	out := []byte{fend, 0x00}
	for _, b := range data {
		switch b {
		case fend:
			out = append(out, fesc, tfend)
		case fesc:
			out = append(out, fesc, tfesc)
		default:
			out = append(out, b)
		}
	}
	return append(out, fend)
}

// kissReader yields the payload of each KISS data frame on port 0.
func kissRead(r *bufio.Reader) ([]byte, error) {
	var frame []byte
	in := false
	for {
		b, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		switch {
		case b == fend:
			if in && len(frame) > 1 && frame[0]&0x0F == 0 {
				return frame[1:], nil
			}
			in, frame = true, frame[:0]
		case !in:
		case b == fesc:
			n, err := r.ReadByte()
			if err != nil {
				return nil, err
			}
			if n == tfend {
				frame = append(frame, fend)
			} else if n == tfesc {
				frame = append(frame, fesc)
			}
		default:
			if len(frame) < 4096 {
				frame = append(frame, b)
			}
		}
	}
}

func ax25Addr(call string, last bool) ([]byte, error) {
	ssid := 0
	if i := strings.IndexByte(call, '-'); i >= 0 {
		if _, err := fmt.Sscanf(call[i+1:], "%d", &ssid); err != nil || ssid < 0 || ssid > 15 {
			return nil, errors.New("ax25: bad SSID in " + call)
		}
		call = call[:i]
	}
	call = strings.ToUpper(call)
	if len(call) == 0 || len(call) > 6 {
		return nil, errors.New("ax25: callsign must be 1..6 characters: " + call)
	}
	out := make([]byte, 7)
	for i := 0; i < 6; i++ {
		c := byte(' ')
		if i < len(call) {
			c = call[i]
		}
		out[i] = c << 1
	}
	out[6] = 0x60 | byte(ssid)<<1
	if last {
		out[6] |= 1
	}
	return out, nil
}

func ax25Call(b []byte) string {
	var sb strings.Builder
	for i := 0; i < 6; i++ {
		if c := b[i] >> 1; c != ' ' {
			sb.WriteByte(c)
		}
	}
	if ssid := (b[6] >> 1) & 0x0F; ssid != 0 {
		fmt.Fprintf(&sb, "-%d", ssid)
	}
	return sb.String()
}

// ax25EncodeUI builds an unnumbered-information frame (control 0x03, PID 0xF0).
func ax25EncodeUI(dst, src string, info []byte) ([]byte, error) {
	d, err := ax25Addr(dst, false)
	if err != nil {
		return nil, err
	}
	s, err := ax25Addr(src, true)
	if err != nil {
		return nil, err
	}
	if len(info) > 256 {
		return nil, errors.New("ax25: information field limited to 256 bytes")
	}
	return append(append(append(d, s...), 0x03, 0xF0), info...), nil
}

// ax25DecodeUI parses a UI frame, skipping any digipeater path.
func ax25DecodeUI(f []byte) (dst, src string, info []byte, err error) {
	if len(f) < 16 {
		return "", "", nil, errors.New("ax25: frame too short")
	}
	dst, src = ax25Call(f[0:7]), ax25Call(f[7:14])
	i := 14
	for f[i-1]&1 == 0 { // address extension bit clear: more addresses follow
		if i+7 > len(f) {
			return "", "", nil, errors.New("ax25: unterminated address field")
		}
		i += 7
	}
	if i+2 > len(f) || f[i]&0xEF != 0x03 || f[i+1] != 0xF0 {
		return "", "", nil, errors.New("ax25: not a UI frame with no layer 3")
	}
	return dst, src, f[i+2:], nil
}

// AX25 connects to a KISS TNC over TCP and exchanges UI frames.
type AX25 struct {
	Addr     string // KISS TCP endpoint of the TNC, e.g. 127.0.0.1:8001
	Callsign string // this station
	Class    int    // classification assigned to traffic on this link

	mu   sync.Mutex
	conn net.Conn
}

func (a *AX25) Name() string { return "ax25" }

func (a *AX25) Run(ctx context.Context, emit func(Envelope)) error {
	for ctx.Err() == nil {
		conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", a.Addr)
		if err != nil {
			select {
			case <-ctx.Done():
			case <-time.After(3 * time.Second):
			}
			continue
		}
		a.mu.Lock()
		a.conn = conn
		a.mu.Unlock()
		stop := context.AfterFunc(ctx, func() { conn.Close() })
		r := bufio.NewReader(conn)
		for {
			f, err := kissRead(r)
			if err != nil {
				break
			}
			dst, src, info, err := ax25DecodeUI(f)
			if err != nil {
				continue
			}
			emit(Envelope{Adapter: "ax25", Origin: src, Destination: dst, Precedence: "ROUTINE", Classification: a.Class, Body: string(info), Raw: f})
		}
		stop()
		a.mu.Lock()
		a.conn = nil
		a.mu.Unlock()
		conn.Close()
	}
	return ctx.Err()
}

func (a *AX25) Send(dest, body string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.conn == nil {
		return errors.New("ax25: TNC link is down")
	}
	// Long messages are split across frames at the 256-byte info limit.
	for len(body) > 0 {
		n := min(len(body), 256)
		f, err := ax25EncodeUI(dest, a.Callsign, []byte(body[:n]))
		if err != nil {
			return err
		}
		a.conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := a.conn.Write(kissEncode(f)); err != nil {
			return err
		}
		body = body[n:]
	}
	return nil
}
