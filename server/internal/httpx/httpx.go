// Package httpx holds small HTTP helpers shared by the services.
package httpx

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
)

type Error struct {
	Status  int      `json:"-"`
	Code    string   `json:"error"`
	Message string   `json:"message"`
	Reasons []string `json:"reasons,omitempty"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

func E(status int, code, msg string) *Error { return &Error{Status: status, Code: code, Message: msg} }

func JSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func Fail(w http.ResponseWriter, err error) {
	var he *Error
	if errors.As(err, &he) {
		JSON(w, he.Status, he)
		return
	}
	JSON(w, http.StatusInternalServerError, &Error{Code: "internal", Message: "internal error"})
	println("internal error:", err.Error())
}

// Decode reads a JSON body of at most max bytes into v, rejecting unknown fields.
func Decode(r *http.Request, max int64, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, max))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return E(http.StatusBadRequest, "bad_request", "invalid JSON body: "+err.Error())
	}
	return nil
}

// ClientIP returns the peer address. X-Forwarded-For is honoured only from
// the loopback/edge proxy (Ring 0 terminator), never from arbitrary peers.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[len(parts)-1])
		}
	}
	return host
}
