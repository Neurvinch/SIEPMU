package policy

import (
	"context"
	"strings"
	"testing"
)

func base() Input {
	in := Input{
		Subject:  Subject{ID: "u1", Unit: "17SQN", Clearance: 3, Compartments: []string{"OPS"}, Roles: []string{"member"}, Status: "active"},
		Device:   Device{ID: "d1", Managed: true, HardwareBound: true, Patched: true, Geofence: "inside"},
		Session:  Session{MFAStrength: 2, Risk: 10, AgeSeconds: 600},
		Resource: Resource{Type: "channel", Classification: 3, Compartments: []string{"OPS"}, Unit: "17SQN", Member: true},
		Action:   "read",
	}
	return in
}

func TestPolicy(t *testing.T) {
	e, err := New(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		mut    func(*Input)
		allow  bool
		reason string
	}{
		{"member with clearance reads", func(*Input) {}, true, ""},
		{"non-member denied", func(i *Input) { i.Resource.Member = false }, false, "no rule grants"},
		{"insufficient clearance", func(i *Input) { i.Subject.Clearance = 2 }, false, "clearance 2 below"},
		{"missing compartment", func(i *Input) { i.Subject.Compartments = nil }, false, "missing compartment OPS"},
		{"unmanaged device", func(i *Input) { i.Device.Managed = false }, false, "managed device"},
		{"unpatched device limited", func(i *Input) { i.Device.Patched = false }, false, "posture limits access to level 1"},
		{"outside geofence", func(i *Input) { i.Device.Geofence = "outside" }, false, "posture"},
		{"unknown geofence ok for confidential", func(i *Input) { i.Device.Geofence = "unknown"; i.Resource.Classification = 2 }, true, ""},
		{"high risk blocks all", func(i *Input) { i.Session.Risk = 85; i.Resource.Classification = 0 }, false, "posture"},
		{"medium risk restricted ok", func(i *Input) { i.Session.Risk = 60; i.Resource.Classification = 1 }, true, ""},
		{"top secret needs smartcard", func(i *Input) { i.Subject.Clearance = 4; i.Resource.Classification = 4 }, false, "smart-card"},
		{"top secret with smartcard", func(i *Input) {
			i.Subject.Clearance = 4
			i.Resource.Classification = 4
			i.Session.MFAStrength = 3
		}, true, ""},
		{"stale session for secret", func(i *Input) { i.Session.AgeSeconds = 20000 }, false, "re-authenticate"},
		{"breakglass raises clearance", func(i *Input) {
			i.Subject.Clearance = 1
			i.Subject.Compartments = nil
			i.Session.Breakglass = &Breakglass{Clearance: 3, Compartments: []string{"OPS"}}
		}, true, ""},
		{"secret export needs purpose", func(i *Input) { i.Resource.Type = "file"; i.Action = "export" }, false, "purpose"},
		{"secret export with purpose", func(i *Input) { i.Resource.Type = "file"; i.Action = "export"; i.Purpose = "mission brief" }, true, ""},
		{"erase without approval", func(i *Input) { i.Resource.Type = "file"; i.Action = "erase"; i.Resource.Owner = true }, false, "commander approval"},
		{"erase with approval", func(i *Input) {
			i.Resource.Type = "file"
			i.Action = "erase"
			i.Resource.Owner = true
			i.Approval.Commander = true
		}, true, ""},
		{"admin needs role", func(i *Input) { i.Resource = Resource{Type: "admin"}; i.Action = "manage" }, false, "no rule"},
		{"admin role", func(i *Input) { i.Resource = Resource{Type: "admin"}; i.Action = "manage"; i.Subject.Roles = []string{"admin"} }, true, ""},
		{"breakglass self-approval", func(i *Input) {
			i.Resource = Resource{Type: "breakglass", Originator: "u1"}
			i.Action = "approve"
			i.Subject.Roles = []string{"commander"}
		}, false, "no rule"},
		{"suspended user", func(i *Input) { i.Subject.Status = "suspended" }, false, "not active"},
	}
	for _, c := range cases {
		in := base()
		c.mut(&in)
		d, err := e.Evaluate(context.Background(), in)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if d.Allow != c.allow {
			t.Errorf("%s: allow=%v want %v (%v)", c.name, d.Allow, c.allow, d.Reasons)
			continue
		}
		if c.reason != "" && !strings.Contains(strings.Join(d.Reasons, "|"), c.reason) {
			t.Errorf("%s: reasons %v missing %q", c.name, d.Reasons, c.reason)
		}
	}
}
