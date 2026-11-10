package bridge

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// ACP-127 style formatted messages as exchanged with military message
// switches. The parser handles the common plain-language layout:
//
//	<routing line>
//	<precedence prosign> <DTG>      e.g.  P 101200Z NOV 26
//	FM <originator>
//	TO <addressee>   (one or more; INFO lines are kept as text)
//	BT
//	<classification line>
//	<text ...>
//	BT
//	NNNN
var (
	acpPrecDTG = regexp.MustCompile(`^([ZOPR]) (\d{6}Z [A-Z]{3} \d{2})$`)
	acpPrec    = map[string]string{"Z": "FLASH", "O": "IMMEDIATE", "P": "PRIORITY", "R": "ROUTINE"}
	acpProsign = map[string]string{"FLASH": "Z", "IMMEDIATE": "O", "PRIORITY": "P", "ROUTINE": "R"}
	acpClass   = []struct {
		prefix string
		level  int
	}{{"TOP SECRET", 4}, {"SECRET", 3}, {"CONFIDENTIAL", 2}, {"RESTRICTED", 1}, {"UNCLASSIFIED", 0}, {"UNCLAS", 0}}
	classWord = []string{"UNCLAS", "RESTRICTED", "CONFIDENTIAL", "SECRET", "TOP SECRET"}
)

// ParseACP127 parses one message (the lines before NNNN).
func ParseACP127(msg string) (Envelope, error) {
	e := Envelope{Adapter: "acp127", Classification: -1}
	var lines []string
	for _, l := range strings.Split(strings.ReplaceAll(msg, "\r", ""), "\n") {
		lines = append(lines, strings.TrimRight(l, " "))
	}
	bt := []int{}
	for i, l := range lines {
		if l == "BT" {
			bt = append(bt, i)
		}
	}
	if len(bt) < 2 {
		return e, errors.New("acp127: message has no BT ... BT text block")
	}
	for _, l := range lines[:bt[0]] {
		switch {
		case acpPrecDTG.MatchString(l):
			m := acpPrecDTG.FindStringSubmatch(l)
			e.Precedence = acpPrec[m[1]]
		case strings.HasPrefix(l, "FM "):
			e.Origin = strings.TrimSpace(l[3:])
		case strings.HasPrefix(l, "TO ") && e.Destination == "":
			e.Destination = strings.TrimSpace(l[3:])
		}
	}
	if e.Precedence == "" || e.Origin == "" || e.Destination == "" {
		return e, errors.New("acp127: missing precedence/DTG, FM or TO line")
	}
	text := lines[bt[0]+1 : bt[len(bt)-1]]
	if len(text) == 0 {
		return e, errors.New("acp127: empty text")
	}
	first := strings.ToUpper(strings.TrimSpace(text[0]))
	for _, c := range acpClass {
		if strings.HasPrefix(first, c.prefix) {
			e.Classification = c.level
			break
		}
	}
	if e.Classification < 0 {
		return e, errors.New("acp127: first text line must be the security classification")
	}
	e.Body = strings.TrimSpace(strings.Join(text[1:], "\n"))
	e.Raw = []byte(msg)
	return e, nil
}

// FormatACP127 renders an outbound message.
func FormatACP127(station string, serial int, e Envelope, now time.Time) string {
	dtg := strings.ToUpper(now.UTC().Format("021504Z Jan 06"))
	p := acpProsign[e.Precedence]
	if p == "" {
		p = "R"
	}
	return fmt.Sprintf("%sAAUZYUW %s%04d %s\r\n%s %s\r\nFM %s\r\nTO %s\r\nBT\r\n%s\r\n%s\r\nBT\r\n#%04d\r\nNNNN\r\n",
		p, station, serial, now.UTC().Format("0021504"), p, dtg, e.Origin, e.Destination, classWord[e.Classification], e.Body, serial)
}

// ACP127 listens for a message-switch feed and dials the switch to send.
type ACP127 struct {
	Listen   string // TCP address the message switch delivers to
	SendAddr string // TCP address of the switch for outbound traffic
	Station  string // this station's routing indicator
	serial   int
}

func (a *ACP127) Name() string { return "acp127" }

func (a *ACP127) Run(ctx context.Context, emit func(Envelope)) error {
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", a.Listen)
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
			sc := bufio.NewScanner(conn)
			sc.Buffer(make([]byte, 64<<10), 256<<10)
			var cur strings.Builder
			for sc.Scan() {
				line := strings.TrimRight(sc.Text(), "\r ")
				if line == "NNNN" {
					if e, err := ParseACP127(cur.String()); err == nil {
						emit(e)
					} else {
						// Unparseable traffic still enters the gate so it is
						// rejected and counted rather than silently dropped.
						emit(Envelope{Adapter: "acp127", Origin: conn.RemoteAddr().String(), Destination: "UNPARSED", Precedence: "ROUTINE", Classification: 0, Body: "", Raw: []byte(cur.String())})
					}
					cur.Reset()
					continue
				}
				if cur.Len() < 256<<10 {
					cur.WriteString(line + "\n")
				}
			}
		}()
	}
}

func (a *ACP127) Send(dest, body string) error {
	if a.SendAddr == "" {
		return errors.New("acp127: no send_addr configured")
	}
	conn, err := net.DialTimeout("tcp", a.SendAddr, 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	a.serial = a.serial%9999 + 1
	// Outbound text carries its own classification line supplied by the mesh.
	lines := strings.SplitN(body, "\n", 2)
	e := Envelope{Origin: a.Station, Destination: dest, Precedence: "ROUTINE"}
	first := strings.ToUpper(strings.TrimSpace(lines[0]))
	matched := false
	for _, c := range acpClass {
		if strings.HasPrefix(first, c.prefix) {
			e.Classification, matched = c.level, true
			break
		}
	}
	if !matched || len(lines) < 2 {
		return errors.New("acp127: outbound text must start with a classification line")
	}
	e.Body = lines[1]
	conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	_, err = conn.Write([]byte(FormatACP127(a.Station, a.serial, e, time.Now())))
	return err
}
