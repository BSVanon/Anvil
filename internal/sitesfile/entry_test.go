package sitesfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseEntry(t *testing.T) {
	tests := []struct {
		raw     string
		want    Entry
		wantErr bool
	}{
		{raw: "Example.COM.", want: Entry{Kind: "domain", Value: "example.com"}},
		{raw: "gw.example.org", want: Entry{Kind: "domain", Value: "gw.example.org"}},
		{
			raw:  "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899_0",
			want: Entry{Kind: "origin", Value: "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899_0"},
		},
		{raw: "not a domain!", wantErr: true},
		{raw: "203.0.113.5", wantErr: true}, // IP literal: refused as a domain
		{raw: "deadbeef_0", wantErr: true},  // too short to be an outpoint; the underscore also fails the domain's LDH rule
	}
	for _, tc := range tests {
		got, err := ParseEntry(tc.raw)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseEntry(%q): want error, got %+v", tc.raw, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseEntry(%q): unexpected error: %v", tc.raw, err)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseEntry(%q) = %+v, want %+v", tc.raw, got, tc.want)
		}
	}
}

func TestValidateDomain_RejectsIPLiteralsAndNonLDH(t *testing.T) {
	bad := []string{"203.0.113.5", "::1", "has a space.com", "under_score.com", "-leadingdash.com", ""}
	for _, d := range bad {
		if _, ok := ValidateDomain(d); ok {
			t.Errorf("ValidateDomain(%q): want refused, got accepted", d)
		}
	}
	good := map[string]string{
		"Example.COM": "example.com",
		"gw.Example.": "gw.example",
		"a-b-c.io":    "a-b-c.io",
	}
	for in, want := range good {
		got, ok := ValidateDomain(in)
		if !ok || got != want {
			t.Errorf("ValidateDomain(%q) = (%q, %v), want (%q, true)", in, got, ok, want)
		}
	}
}

func TestRead_MissingFileIsEmptyNotError(t *testing.T) {
	entries, err := Read(filepath.Join(t.TempDir(), "does-not-exist.conf"))
	if err != nil {
		t.Fatalf("Read on a missing file returned an error: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("Read on a missing file returned %d entries, want 0", len(entries))
	}
}

func TestRead_SkipsCommentsBlanksAndMalformedLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sites.conf")
	content := "# a comment\n\ndomain example.com\nbogus line here\norigin aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899_1\ndomain not valid!\n"
	if err := os.WriteFile(path, []byte(content), 0640); err != nil {
		t.Fatal(err)
	}
	entries, err := Read(path)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2: %+v", len(entries), entries)
	}
	if entries[0] != (Entry{Kind: "domain", Value: "example.com"}) {
		t.Errorf("entries[0] = %+v", entries[0])
	}
	if entries[1].Kind != "origin" {
		t.Errorf("entries[1] = %+v, want kind origin", entries[1])
	}
}
