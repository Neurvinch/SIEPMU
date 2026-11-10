package bridge

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Spool is the durable store-and-forward queue. One file per envelope,
// written with fsync + atomic rename, so nothing accepted from a legacy
// link is lost if the bridge crashes or the mesh is unreachable.
type Spool struct{ Dir string }

func (s Spool) Put(e Signed) error {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	final := filepath.Join(s.Dir, e.ID+".json")
	if _, err := os.Stat(final); err == nil {
		return nil // G-Set: adding an existing element is a no-op
	}
	b, _ := json.Marshal(e)
	tmp := final + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	f.Close()
	return os.Rename(tmp, final)
}

// Pending returns spooled envelopes ordered by precedence (command-critical
// traffic first) and then by hybrid logical clock.
func (s Spool) Pending(limit int) ([]Signed, error) {
	entries, err := os.ReadDir(s.Dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	type item struct {
		s    Signed
		rank int
		hlc  int64
	}
	var items []item
	for _, de := range entries {
		if !strings.HasSuffix(de.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(s.Dir, de.Name()))
		if err != nil {
			continue
		}
		var sg Signed
		var e Envelope
		if json.Unmarshal(b, &sg) != nil || json.Unmarshal(sg.Envelope, &e) != nil {
			continue
		}
		items = append(items, item{sg, Rank(e.Precedence), e.HLC})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].rank != items[j].rank {
			return items[i].rank < items[j].rank
		}
		return items[i].hlc < items[j].hlc
	})
	if len(items) > limit {
		items = items[:limit]
	}
	out := make([]Signed, len(items))
	for i, it := range items {
		out[i] = it.s
	}
	return out, nil
}

func (s Spool) Ack(id string) error {
	err := os.Remove(filepath.Join(s.Dir, id+".json"))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
