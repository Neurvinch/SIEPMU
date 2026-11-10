package monitor

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Neurvinch/SIEPMU/server/internal/events"
)

func rec(t *testing.T, s string) map[string]any {
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestNormalise(t *testing.T) {
	e, ok := normalise("suricata", rec(t, `{"timestamp":"2026-11-10T12:00:01.123456+0000","event_type":"alert","src_ip":"203.0.113.9","dest_ip":"10.0.0.5","dest_port":443,"proto":"TCP","alert":{"signature":"ET SCAN Nmap","category":"Attempted Recon","severity":1,"signature_id":2009582,"metadata":{"mitre_technique_id":["T1046"]}}}`))
	if !ok || e.Severity != 4 || e.IP != "203.0.113.9" || len(e.AttackIDs) != 1 || e.Summary != "ET SCAN Nmap" || e.Time.Year() != 2026 {
		t.Fatalf("suricata: %+v", e)
	}
	if _, ok := normalise("suricata", rec(t, `{"event_type":"flow"}`)); ok {
		t.Fatal("flow record should be skipped")
	}
	e, ok = normalise("falco", rec(t, `{"time":"2026-11-10T12:00:00.000000000Z","priority":"Critical","rule":"Terminal shell in container","output":"A shell was spawned","tags":["container","mitre_execution","T1059"],"hostname":"node1","output_fields":{"container.id":"abc"}}`))
	if !ok || e.Severity != 4 || e.AttackIDs[0] != "T1059" {
		t.Fatalf("falco: %+v", e)
	}
	e, ok = normalise("wazuh", rec(t, `{"timestamp":"2026-11-10T12:00:00.000+0000","rule":{"level":10,"description":"sshd: brute force","id":"5712","mitre":{"id":["T1110"]},"groups":["sshd"]},"agent":{"name":"web1","ip":"10.0.0.7"},"data":{"srcip":"198.51.100.4"}}`))
	if !ok || e.Severity != 3 || e.IP != "198.51.100.4" || e.AttackIDs[0] != "T1110" {
		t.Fatalf("wazuh: %+v", e)
	}
	e, ok = normalise("zeek", rec(t, `{"ts":1794312000.5,"note":"Scan::Port_Scan","msg":"scanned 50 ports","src":"203.0.113.9","dst":"10.0.0.5"}`))
	if !ok || e.Severity != 3 || e.AttackIDs[0] != "T1046" {
		t.Fatalf("zeek: %+v", e)
	}
}

func TestImpossibleTravel(t *testing.T) {
	now := time.Now().UTC()
	e := events.SecEvent{Time: now, UserID: "u", Data: map[string]any{"lat": 28.6, "lon": 77.2, "prev_lat": 13.08, "prev_lon": 80.27, "prev_time": now.Add(-30 * time.Minute).Format(time.RFC3339)}}
	if _, ok := impossibleTravel(e); !ok {
		t.Fatal("Chennai->Delhi in 30 min must be flagged")
	}
	e.Data["prev_time"] = now.Add(-5 * time.Hour).Format(time.RFC3339)
	if _, ok := impossibleTravel(e); ok {
		t.Fatal("Chennai->Delhi in 5 h is feasible")
	}
}
