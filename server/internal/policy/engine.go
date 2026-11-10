// Package policy evaluates the embedded OPA/Rego ABAC policy for every API
// request. The policy is compiled once at start-up; evaluation is in-process.
package policy

import (
	"context"
	"embed"
	"fmt"

	"github.com/open-policy-agent/opa/v1/rego"
)

//go:embed rego/*.rego
var policyFS embed.FS

type Subject struct {
	ID            string   `json:"id"`
	ServiceNumber string   `json:"service_number"`
	Rank          string   `json:"rank"`
	Unit          string   `json:"unit"`
	Clearance     int      `json:"clearance"`
	Compartments  []string `json:"compartments"`
	Roles         []string `json:"roles"`
	Status        string   `json:"status"`
}

type Device struct {
	ID            string `json:"id"`
	Managed       bool   `json:"managed"`
	HardwareBound bool   `json:"hardware_bound"`
	Patched       bool   `json:"patched"`
	Geofence      string `json:"geofence"` // inside | outside | unknown
}

type Breakglass struct {
	Clearance    int      `json:"clearance"`
	Compartments []string `json:"compartments"`
}

type Session struct {
	MFAStrength int         `json:"mfa_strength"`
	Risk        int         `json:"risk"`
	AgeSeconds  int64       `json:"age_seconds"`
	Breakglass  *Breakglass `json:"breakglass,omitempty"`
}

type Resource struct {
	Type           string   `json:"type"`
	ID             string   `json:"id,omitempty"`
	Classification int      `json:"classification"`
	Compartments   []string `json:"compartments,omitempty"`
	Unit           string   `json:"unit,omitempty"`
	Originator     string   `json:"originator,omitempty"`
	Member         bool     `json:"member"`
	Owner          bool     `json:"owner"`
}

type Input struct {
	Subject  Subject  `json:"subject"`
	Device   Device   `json:"device"`
	Session  Session  `json:"session"`
	Resource Resource `json:"resource"`
	Action   string   `json:"action"`
	Purpose  string   `json:"purpose,omitempty"`
	Approval struct {
		Commander bool `json:"commander"`
	} `json:"approval"`
}

type Decision struct {
	Allow   bool     `json:"allow"`
	Reasons []string `json:"reasons"`
}

type Engine struct {
	q rego.PreparedEvalQuery
}

func New(ctx context.Context) (*Engine, error) {
	src, err := policyFS.ReadFile("rego/authz.rego")
	if err != nil {
		return nil, err
	}
	q, err := rego.New(
		rego.Query("data.siepmu.authz.decision"),
		rego.Module("authz.rego", string(src)),
		rego.StrictBuiltinErrors(true),
	).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("policy: compile: %w", err)
	}
	return &Engine{q: q}, nil
}

func (e *Engine) Evaluate(ctx context.Context, in Input) (Decision, error) {
	if in.Subject.Compartments == nil {
		in.Subject.Compartments = []string{}
	}
	if in.Resource.Compartments == nil {
		in.Resource.Compartments = []string{}
	}
	rs, err := e.q.Eval(ctx, rego.EvalInput(in))
	if err != nil {
		return Decision{}, err
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return Decision{Reasons: []string{"policy produced no decision"}}, nil
	}
	m, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return Decision{Reasons: []string{"policy decision malformed"}}, nil
	}
	d := Decision{}
	d.Allow, _ = m["allow"].(bool)
	if rr, ok := m["reasons"].([]any); ok {
		for _, r := range rr {
			if s, ok := r.(string); ok {
				d.Reasons = append(d.Reasons, s)
			}
		}
	}
	return d, nil
}
