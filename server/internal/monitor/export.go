package monitor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/Neurvinch/SIEPMU/server/internal/config"
	"github.com/Neurvinch/SIEPMU/server/internal/events"
)

// exporter forwards normalised events to the external SIEM: bulk-indexed
// into OpenSearch (when configured) and appended as JSON lines to a file a
// Wazuh agent tails via <localfile><log_format>json</log_format>.
type exporter struct {
	cfg  *config.Config
	mu   sync.Mutex
	buf  []exportDoc
	file *os.File
}

type exportDoc struct {
	ID int64 `json:"-"`
	events.SecEvent
	Timestamp time.Time `json:"@timestamp"`
}

func newExporter(cfg *config.Config) *exporter {
	x := &exporter{cfg: cfg}
	if p := cfg.Monitor.WazuhLogFile; p != "" {
		f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
		if err != nil {
			fmt.Printf("monitor: wazuh log file: %v\n", err)
		} else {
			x.file = f
		}
	}
	return x
}

func (x *exporter) enqueue(id int64, e events.SecEvent) {
	d := exportDoc{ID: id, SecEvent: e, Timestamp: e.Time}
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.file != nil {
		b, _ := json.Marshal(d)
		x.file.Write(append(b, '\n'))
	}
	if x.cfg.Monitor.OpenSearchURL != "" && len(x.buf) < 50000 {
		x.buf = append(x.buf, d)
	}
}

func (x *exporter) run(ctx context.Context) {
	if x.cfg.Monitor.OpenSearchURL == "" {
		return
	}
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			x.flush(ctx)
		}
	}
}

func (x *exporter) flush(ctx context.Context) {
	x.mu.Lock()
	batch := x.buf
	x.buf = nil
	x.mu.Unlock()
	if len(batch) == 0 {
		return
	}
	var body bytes.Buffer
	for _, d := range batch {
		fmt.Fprintf(&body, "{\"index\":{\"_index\":%q,\"_id\":\"%d\"}}\n", x.cfg.Monitor.OpenSearchIndex, d.ID)
		b, _ := json.Marshal(d)
		body.Write(b)
		body.WriteByte('\n')
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, x.cfg.Monitor.OpenSearchURL+"/_bulk", &body)
	req.Header.Set("Content-Type", "application/x-ndjson")
	if x.cfg.Monitor.OpenSearchUser != "" {
		req.SetBasicAuth(x.cfg.Monitor.OpenSearchUser, x.cfg.Monitor.OpenSearchPass)
	}
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode < 300 {
			return
		}
		err = fmt.Errorf("status %s", resp.Status)
	}
	fmt.Printf("monitor: OpenSearch bulk export failed (%v); retrying %d events\n", err, len(batch))
	x.mu.Lock()
	x.buf = append(batch, x.buf...) // ids make the retry idempotent
	x.mu.Unlock()
}
