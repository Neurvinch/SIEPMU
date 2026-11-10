# SIEPMU-SX attribute-based access control. Deny by default: a request is
# allowed only when `allow` is true AND no `deny` reason fires. The policy
# evaluates the six attribute classes of the design: subject identity,
# device posture, session state, resource classification, operation purpose
# and commander approval.
#
# Classification levels: 0 UNCLASSIFIED, 1 RESTRICTED, 2 CONFIDENTIAL,
# 3 SECRET, 4 TOP SECRET.
package siepmu.authz

import rego.v1

default allow := false

# ---------------------------------------------------------------- helpers

effective_clearance := max({input.subject.clearance, bg_clearance})

bg_clearance := input.session.breakglass.clearance if input.session.breakglass
bg_clearance := 0 if not input.session.breakglass

effective_compartments := {c | some c in input.subject.compartments} | bg_compartments

bg_compartments := {c | some c in input.session.breakglass.compartments} if input.session.breakglass
bg_compartments := set() if not input.session.breakglass

has_role(r) if r in input.subject.roles

resource_level := object.get(input.resource, "classification", 0)

# Highest classification this device/session combination may touch.
posture_ceiling := min({device_ceiling, geo_ceiling, risk_ceiling})

device_ceiling := 4 if input.device.patched
device_ceiling := 1 if not input.device.patched

geo_ceiling := 4 if input.device.geofence == "inside"
geo_ceiling := 2 if input.device.geofence == "unknown"
geo_ceiling := 1 if input.device.geofence == "outside"

risk_ceiling := 4 if input.session.risk < 50
risk_ceiling := 1 if {
	input.session.risk >= 50
	input.session.risk < 80
}
risk_ceiling := -1 if input.session.risk >= 80

# Maximum session age (seconds) before re-authentication, by level.
max_session_age := {0: 43200, 1: 43200, 2: 28800, 3: 14400, 4: 7200}

# ---------------------------------------------------------------- deny rules

deny contains "subject is not active" if input.subject.status != "active"

deny contains "device is not an approved managed device" if not input.device.managed

deny contains "device key is not hardware-bound" if not input.device.hardware_bound

deny contains msg if {
	resource_level > effective_clearance
	msg := sprintf("clearance %d below resource classification %d", [effective_clearance, resource_level])
}

deny contains msg if {
	some c in object.get(input.resource, "compartments", [])
	not c in effective_compartments
	msg := sprintf("missing compartment %s", [c])
}

deny contains msg if {
	resource_level > posture_ceiling
	msg := sprintf("device/session posture limits access to level %d (patched=%v geofence=%s risk=%d)", [posture_ceiling, input.device.patched, input.device.geofence, input.session.risk])
}

deny contains "TOP SECRET requires smart-card plus FIDO2 (MFA strength 3)" if {
	resource_level >= 4
	input.session.mfa_strength < 3
}

deny contains "session too old for this classification; re-authenticate" if {
	input.session.age_seconds > max_session_age[resource_level]
}

deny contains "SECRET and above export requires a stated purpose" if {
	input.action == "export"
	resource_level >= 3
	count(trim_space(object.get(input, "purpose", ""))) == 0
}

deny contains "cryptographic erasure requires commander approval" if {
	input.action == "erase"
	not input.approval.commander
	not has_role("commander")
}

# ---------------------------------------------------------------- allow rules

# Channel and file content: members only.
allow if {
	input.resource.type in {"channel", "file"}
	input.action in {"read", "write", "export"}
	input.resource.member
}

# Creating a channel/file in your own unit (or as admin).
allow if {
	input.resource.type in {"channel", "file"}
	input.action == "create"
	input.resource.unit == input.subject.unit
}

allow if {
	input.resource.type in {"channel", "file"}
	input.action == "create"
	has_role("admin")
}

# Channel owners manage membership.
allow if {
	input.resource.type == "channel"
	input.action == "manage"
	input.resource.owner
}

# File owners or commanders may erase.
allow if {
	input.resource.type == "file"
	input.action == "erase"
	input.resource.owner
}

allow if {
	input.resource.type == "file"
	input.action == "erase"
	has_role("commander")
	input.resource.unit == input.subject.unit
}

# Directory lookups and key packages are needed to start conversations.
allow if {
	input.resource.type == "directory"
	input.action == "read"
}

# Administration.
allow if {
	input.resource.type == "admin"
	has_role("admin")
}

# Security operations centre.
allow if {
	input.resource.type == "soc"
	has_role("soc")
}

# Commander dashboard for the commander's own unit.
allow if {
	input.resource.type == "unit"
	input.action == "read"
	has_role("commander")
	input.resource.unit == input.subject.unit
}

# Audit evidence.
allow if {
	input.resource.type == "audit"
	input.action == "read"
	some r in {"auditor", "soc", "admin"}
	has_role(r)
}

# Break-glass approvals: commanders and admins, never the requester.
allow if {
	input.resource.type == "breakglass"
	input.action == "approve"
	some r in {"commander", "admin"}
	has_role(r)
	input.resource.originator != input.subject.id
}

allow if {
	input.resource.type == "breakglass"
	input.action == "create"
}

allow if {
	input.resource.type == "breakglass"
	input.action == "review"
	has_role("auditor")
}

# Cross-domain guard: any user may submit; release officers approve.
allow if {
	input.resource.type == "guard"
	input.action == "create"
}

allow if {
	input.resource.type == "guard"
	input.action == "approve"
	has_role("release_officer")
	input.resource.originator != input.subject.id
}

allow if {
	input.resource.type == "guard"
	input.action == "read"
	some r in {"release_officer", "auditor"}
	has_role(r)
}

# Self-service on one's own account (devices, sessions, notifications).
allow if {
	input.resource.type == "self"
}

# ---------------------------------------------------------------- decision

decision := {
	"allow": count(deny) == 0,
	"reasons": [r | some r in deny],
} if allow

decision := {
	"allow": false,
	"reasons": array.concat(["no rule grants this action"], [r | some r in deny]),
} if not allow
