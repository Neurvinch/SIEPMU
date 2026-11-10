package guard

import (
	"bytes"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// Finding is one content-filter result.
type Finding struct {
	Check  string `json:"check"`
	Pass   bool   `json:"pass"`
	Detail string `json:"detail"`
}

type Report struct {
	Findings     []Finding `json:"findings"`
	Blocked      bool      `json:"blocked"`
	DetectedType string    `json:"detected_type"`
}

type FilterConfig struct {
	MaxSize      int64
	AllowedTypes []string
	DirtyWords   []string
}

// Inspect runs the automated release filter. A single failed check blocks
// the release before any human sees it.
func Inspect(cfg FilterConfig, filename, declaredType string, content []byte) Report {
	var rep Report
	add := func(check string, pass bool, detail string) {
		rep.Findings = append(rep.Findings, Finding{check, pass, detail})
		if !pass {
			rep.Blocked = true
		}
	}
	add("size", int64(len(content)) <= cfg.MaxSize && len(content) > 0, fmt.Sprintf("%d bytes (limit %d)", len(content), cfg.MaxSize))

	// Type is determined from content, never trusted from the client.
	detected := strings.SplitN(http.DetectContentType(content), ";", 2)[0]
	if detected == "text/plain" && (strings.HasSuffix(strings.ToLower(filename), ".json")) {
		detected = "application/json"
	}
	if detected == "application/octet-stream" && utf8.Valid(content) {
		detected = "text/plain"
	}
	rep.DetectedType = detected
	allowed := false
	for _, t := range cfg.AllowedTypes {
		if t == detected {
			allowed = true
		}
	}
	add("type_allowed", allowed, "content sniffed as "+detected)
	add("type_matches_declared", declaredType == "" || strings.SplitN(declaredType, ";", 2)[0] == detected, fmt.Sprintf("declared %q, detected %q", declaredType, detected))

	name := filepath.Base(filename)
	add("filename", name == filename && !strings.ContainsAny(name, "\x00/\\") && name != "" && name != "." && name != ".." && len(name) <= 200, "filename must be a plain base name")

	// Executable / active-content signatures are never released.
	sigs := map[string][]byte{"ELF executable": {0x7f, 'E', 'L', 'F'}, "Windows executable": {'M', 'Z'}, "ZIP/Office archive": {'P', 'K', 0x03, 0x04}, "shell script": []byte("#!")}
	active := ""
	for label, s := range sigs {
		if bytes.HasPrefix(content, s) {
			active = label
		}
	}
	if detected == "application/pdf" {
		for _, tok := range []string{"/JavaScript", "/JS", "/Launch", "/EmbeddedFile", "/OpenAction"} {
			if bytes.Contains(content, []byte(tok)) {
				active = "PDF active content " + tok
			}
		}
	}
	add("no_active_content", active == "", map[bool]string{true: "no executable or active content signatures", false: active}[active == ""])

	if strings.HasPrefix(detected, "text/") || detected == "application/json" {
		add("valid_utf8", utf8.Valid(content), "text must be valid UTF-8")
		ctl := 0
		for _, b := range content {
			if b < 0x20 && b != '\n' && b != '\r' && b != '\t' {
				ctl++
			}
		}
		add("no_control_chars", ctl == 0, fmt.Sprintf("%d control characters", ctl))
	}
	// Dirty-word scan over the raw bytes, case-insensitive.
	lower := bytes.ToLower(content)
	var hits []string
	for _, wd := range cfg.DirtyWords {
		if wd != "" && bytes.Contains(lower, []byte(strings.ToLower(wd))) {
			hits = append(hits, wd)
		}
	}
	add("dirty_words", len(hits) == 0, map[bool]string{true: fmt.Sprintf("%d terms checked, none found", len(cfg.DirtyWords)), false: "found: " + strings.Join(hits, ", ")}[len(hits) == 0])
	return rep
}
