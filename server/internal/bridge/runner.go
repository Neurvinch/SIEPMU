package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Neurvinch/SIEPMU/server/internal/cryptoprov"
)

// Adapter is one legacy link.
type Adapter interface {
	Name() string
	Run(ctx context.Context, emit func(Envelope)) error
	Send(destination, body string) error
}

// Runner ties adapters, the spool and the mesh sync loop together.
type Runner struct {
	Name     string
	CoreURL  string
	Client   *http.Client // mTLS client presenting the bridge SVID
	Signer   cryptoprov.Signer
	Spool    Spool
	Adapters []Adapter
	Interval time.Duration
	clock    HLC
}

func (r *Runner) Run(ctx context.Context) error {
	for _, a := range r.Adapters {
		go func(a Adapter) {
			err := a.Run(ctx, func(e Envelope) {
				e.Bridge = r.Name
				e.HLC = r.clock.Now()
				sg, err := Sign(r.Signer, e)
				if err == nil {
					err = r.Spool.Put(sg)
				}
				if err != nil {
					log.Printf("bridge: spool %s message: %v", a.Name(), err)
				}
			})
			if err != nil && ctx.Err() == nil {
				log.Printf("bridge: adapter %s stopped: %v", a.Name(), err)
			}
		}(a)
	}
	t := time.NewTicker(r.Interval)
	defer t.Stop()
	for {
		if err := r.syncOnce(ctx); err != nil && ctx.Err() == nil {
			log.Printf("bridge: mesh unreachable, traffic held in spool: %v", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

func (r *Runner) call(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, r.CoreURL+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s %s: %s %s", method, path, resp.Status, b)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (r *Runner) syncOnce(ctx context.Context) error {
	for {
		pend, err := r.Spool.Pending(100)
		if err != nil {
			return err
		}
		if len(pend) == 0 {
			break
		}
		verdicts := map[string]string{}
		if err := r.call(ctx, http.MethodPost, "/mesh/bridge/inbound", pend, &verdicts); err != nil {
			return err
		}
		progressed := false
		for id, v := range verdicts {
			if strings.HasPrefix(v, "retry") {
				continue
			}
			if strings.HasPrefix(v, "rejected") {
				log.Printf("bridge: mesh gate %s for %s", v, id[:12])
			}
			if err := r.Spool.Ack(id); err == nil {
				progressed = true
			}
		}
		if !progressed {
			break
		}
	}
	var out []struct {
		ID, Adapter, Destination, Body string
	}
	if err := r.call(ctx, http.MethodGet, "/mesh/bridge/outbound", nil, &out); err != nil {
		return err
	}
	var sent []string
	for _, o := range out {
		for _, a := range r.Adapters {
			if a.Name() != o.Adapter {
				continue
			}
			if err := a.Send(o.Destination, o.Body); err != nil {
				log.Printf("bridge: %s link send failed, will retry: %v", o.Adapter, err)
			} else {
				sent = append(sent, o.ID)
			}
		}
	}
	if len(sent) > 0 {
		return r.call(ctx, http.MethodPost, "/mesh/bridge/outbound/ack", sent, nil)
	}
	return nil
}
