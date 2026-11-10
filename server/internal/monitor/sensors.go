package monitor

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Neurvinch/SIEPMU/server/internal/events"
	"github.com/Neurvinch/SIEPMU/server/internal/httpx"
	"github.com/Neurvinch/SIEPMU/server/internal/pki"
)

// Sensor ingestion. Sensors (or their log shippers) POST their native JSON
// to /ingest/{sensor} on the mesh listener, authenticated by an mTLS
// workload certificate whose SPIFFE ID is sensor/<name>. Each native record
// is normalised into a SecEvent and published, signed, to the SEC stream.

var techniqueRE = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)

func techniques(vals ...any) []string {
	out := []string{}
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case string:
			if techniqueRE.MatchString(x) {
				out = append(out, x)
			}
		case []any:
			for _, y := range x {
				walk(y)
			}
		}
	}
	for _, v := range vals {
		walk(v)
	}
	return out
}

func str(m map[string]any, path ...string) string {
	var cur any = m
	for _, p := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = mm[p]
	}
	s, _ := cur.(string)
	return s
}

func num(m map[string]any, path ...string) (float64, bool) {
	var cur any = m
	for _, p := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return 0, false
		}
		cur = mm[p]
	}
	f, ok := cur.(float64)
	return f, ok
}

func parseTime(s string) time.Time {
	for _, l := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999-0700", "2006-01-02T15:04:05.000-0700"} {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC()
		}
	}
	return time.Now().UTC()
}

// normalise converts one native sensor record. ok=false means the record is
// not security-relevant (e.g. a Suricata flow record) and is skipped.
func normalise(sensor string, r map[string]any) (events.SecEvent, bool) {
	switch sensor {
	case "suricata": // EVE JSON
		if str(r, "event_type") != "alert" {
			return events.SecEvent{}, false
		}
		sev := 2
		if s, ok := num(r, "alert", "severity"); ok { // 1 = highest
			sev = map[int]int{1: 4, 2: 3, 3: 2}[int(s)]
			if sev == 0 {
				sev = 1
			}
		}
		md, _ := r["alert"].(map[string]any)
		var meta map[string]any
		if md != nil {
			meta, _ = md["metadata"].(map[string]any)
		}
		return events.SecEvent{Time: parseTime(str(r, "timestamp")), Source: "suricata", Kind: "sensor.network_alert", Severity: sev, IP: str(r, "src_ip"),
			AttackIDs: techniques(meta["mitre_technique_id"]), Summary: str(r, "alert", "signature"),
			Data: map[string]any{"dest_ip": str(r, "dest_ip"), "dest_port": r["dest_port"], "proto": str(r, "proto"), "category": str(r, "alert", "category"), "signature_id": md["signature_id"]}}, true
	case "zeek": // notice.log (JSON)
		note := str(r, "note")
		if note == "" {
			return events.SecEvent{}, false
		}
		t := time.Now().UTC()
		if ts, ok := num(r, "ts"); ok {
			t = time.Unix(0, int64(ts*1e9)).UTC()
		}
		sev := 2
		if strings.Contains(note, "Scan") {
			sev = 3
		}
		att := []string{}
		if strings.Contains(note, "Scan") {
			att = []string{"T1046"}
		}
		return events.SecEvent{Time: t, Source: "zeek", Kind: "sensor.network_notice", Severity: sev, IP: str(r, "src"), AttackIDs: att,
			Summary: note + ": " + str(r, "msg"), Data: map[string]any{"dst": str(r, "dst"), "note": note, "sub": str(r, "sub")}}, true
	case "falco":
		sev := map[string]int{"emergency": 4, "alert": 4, "critical": 4, "error": 3, "warning": 2, "notice": 1, "informational": 0, "debug": 0}[strings.ToLower(str(r, "priority"))]
		return events.SecEvent{Time: parseTime(str(r, "time")), Source: "falco", Kind: "sensor.runtime_alert", Severity: sev,
			AttackIDs: techniques(r["tags"]), Summary: str(r, "rule") + ": " + str(r, "output"),
			Data: map[string]any{"hostname": str(r, "hostname"), "output_fields": r["output_fields"], "tags": r["tags"]}}, true
	case "wazuh":
		lvl, _ := num(r, "rule", "level") // 0..15
		sev := 0
		switch {
		case lvl >= 12:
			sev = 4
		case lvl >= 9:
			sev = 3
		case lvl >= 6:
			sev = 2
		case lvl >= 3:
			sev = 1
		}
		rule, _ := r["rule"].(map[string]any)
		var mitre map[string]any
		if rule != nil {
			mitre, _ = rule["mitre"].(map[string]any)
		}
		ip := str(r, "data", "srcip")
		if ip == "" {
			ip = str(r, "agent", "ip")
		}
		return events.SecEvent{Time: parseTime(str(r, "timestamp")), Source: "wazuh", Kind: "sensor.endpoint_alert", Severity: sev, IP: ip,
			AttackIDs: techniques(mitre["id"]), Summary: str(r, "rule", "description"),
			Data: map[string]any{"agent": str(r, "agent", "name"), "rule_id": str(r, "rule", "id"), "level": lvl, "groups": rule["groups"], "location": str(r, "location")}}, true
	}
	return events.SecEvent{}, false
}

// IngestHandler serves POST /ingest/{sensor} on the mTLS mesh listener.
func (m *Monitor) IngestHandler(w http.ResponseWriter, r *http.Request) {
	sensor := r.PathValue("sensor")
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		httpx.Fail(w, httpx.E(401, "unauthenticated", "mTLS workload certificate required"))
		return
	}
	wid, err := pki.WorkloadIdentity(r.TLS.PeerCertificates[0])
	if err != nil || wid != "sensor/"+sensor {
		httpx.Fail(w, httpx.E(403, "forbidden", fmt.Sprintf("workload %q may not publish as sensor %q", wid, sensor)))
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
	if err != nil {
		httpx.Fail(w, httpx.E(400, "bad_request", err.Error()))
		return
	}
	var records []map[string]any
	trim := bytes.TrimSpace(body)
	if len(trim) > 0 && trim[0] == '[' {
		if err := json.Unmarshal(trim, &records); err != nil {
			httpx.Fail(w, httpx.E(400, "bad_request", "invalid JSON array"))
			return
		}
	} else { // single object or NDJSON
		sc := bufio.NewScanner(bytes.NewReader(trim))
		sc.Buffer(make([]byte, 1<<20), 4<<20)
		for sc.Scan() {
			line := bytes.TrimSpace(sc.Bytes())
			if len(line) == 0 {
				continue
			}
			var rec map[string]any
			if err := json.Unmarshal(line, &rec); err != nil {
				httpx.Fail(w, httpx.E(400, "bad_request", "invalid JSON record"))
				return
			}
			records = append(records, rec)
		}
	}
	accepted := 0
	for _, rec := range records {
		e, ok := normalise(sensor, rec)
		if !ok {
			continue
		}
		if err := m.bus.PublishSec(r.Context(), e); err != nil {
			httpx.Fail(w, err)
			return
		}
		accepted++
	}
	httpx.JSON(w, 202, map[string]int{"received": len(records), "accepted": accepted})
}
