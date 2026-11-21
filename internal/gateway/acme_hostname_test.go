package gateway

import (
	"strings"
	"testing"
)

// ── isValidHostname ──

func TestIsValidHostname(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"allowed.example.org", true},
		{"UPPER.Example.org", true}, // ValidateDomain normalises case
		{"a.b", true},
		{"localhost", false},               // no dot
		{"", false},                        // empty
		{"..", false},                      // no label at all
		{"../../x", false},                 // path traversal shape
		{"a/b.example", false},             // '/' is not a label character
		{"-leading-hyphen.example", false}, // label can't start with '-'
		{"trailing-hyphen-.example", false},
		{strings.Repeat("a", 300) + ".example.org", false}, // over 253 total
		{"has space.example", false},
		{"has\x00nul.example", false},
	}
	for _, c := range cases {
		got, ok := isValidHostname(c.name)
		if ok != c.want {
			t.Errorf("isValidHostname(%q) ok = %v, want %v", c.name, ok, c.want)
		}
		if ok && got == "" {
			t.Errorf("isValidHostname(%q) returned ok=true with an empty normalised form", c.name)
		}
	}
}

// TestIsValidHostname_NormalisesCase confirms the returned string is
// always lowercase, regardless of the input's case — the form
// errorNotePath and ApplyReceived's "+token" branch both build a path or
// a cache key from.
func TestIsValidHostname_NormalisesCase(t *testing.T) {
	got, ok := isValidHostname("UPPER.Example.ORG")
	if !ok {
		t.Fatal("isValidHostname(\"UPPER.Example.ORG\") refused a syntactically valid hostname")
	}
	if got != "upper.example.org" {
		t.Errorf("isValidHostname(\"UPPER.Example.ORG\") = %q, want %q", got, "upper.example.org")
	}
}

// ── isValidACMEToken ──

func TestIsValidACMEToken(t *testing.T) {
	cases := []struct {
		token string
		want  bool
	}{
		{"tok", true},
		{"tok123", true},
		{"brand-new-token", true},
		{"longlived", true}, // letters only — valid charset, even though it's not a "complete" base64 group
		{"sometoken", true}, // same
		{"ABC_def-123", true},
		{"", false},        // empty
		{"a/b", false},     // '/' is outside the base64url alphabet
		{"../../x", false}, // path traversal shape
		{"has space", false},
		{"has\x00nul", false},
		{strings.Repeat("a", 129), false}, // over the length cap
		{strings.Repeat("a", 128), true},  // at the cap
	}
	for _, c := range cases {
		if got := isValidACMEToken(c.token); got != c.want {
			t.Errorf("isValidACMEToken(%q) = %v, want %v", c.token, got, c.want)
		}
	}
}

// ── errorNotePath ──

func TestErrorNotePath_RefusesHostileNames(t *testing.T) {
	dir := "/tmp/example-acme-dir"
	for _, name := range []string{
		"../../x",
		"a/b.example",
		"..",
		"",
		"localhost", // no dot
		"has\x00nul.example",
		strings.Repeat("a", 300) + ".example.org",
	} {
		if _, err := errorNotePath(dir, name); err == nil {
			t.Errorf("errorNotePath(%q, %q) succeeded, want refused", dir, name)
		}
	}
}

// TestErrorNotePath_AnchorsInsideDirForValidNames confirms a valid
// hostname always produces a path inside dir — the anchoring
// cache.go:43/84/98 uses, cited in errorNotePath's own doc comment.
func TestErrorNotePath_AnchorsInsideDirForValidNames(t *testing.T) {
	dir := "/tmp/example-acme-dir"
	for _, name := range []string{"allowed.example.org", "UPPER.Example.org", "a.b"} {
		path, err := errorNotePath(dir, name)
		if err != nil {
			t.Fatalf("errorNotePath(%q, %q): %v", dir, name, err)
		}
		if !strings.HasPrefix(path, dir+"/") {
			t.Errorf("errorNotePath(%q, %q) = %q, want a path inside %q", dir, name, path, dir)
		}
		if strings.Contains(path, "..") {
			t.Errorf("errorNotePath(%q, %q) = %q, contains \"..\"", dir, name, path)
		}
	}
}
