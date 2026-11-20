package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateSiteDomain(t *testing.T) {
	ok := []string{"example.com", "sub.example.com", "EXAMPLE.com", "example.com.", "a.b.c.example"}
	for _, d := range ok {
		if _, valid := validateSiteDomain(d); !valid {
			t.Errorf("validateSiteDomain(%q) = invalid, want valid", d)
		}
	}
	if got, _ := validateSiteDomain("EXAMPLE.com"); got != "example.com" {
		t.Errorf("validateSiteDomain did not lowercase: got %q", got)
	}
	if got, _ := validateSiteDomain("example.com."); got != "example.com" {
		t.Errorf("validateSiteDomain did not strip trailing dot: got %q", got)
	}

	bad := []string{"", "127.0.0.1", "::1", "-example.com", "example-.com", "exa mple.com", "exa_mple.com"}
	for _, d := range bad {
		if _, valid := validateSiteDomain(d); valid {
			t.Errorf("validateSiteDomain(%q) = valid, want invalid", d)
		}
	}
}

func TestValidateSiteOrigin(t *testing.T) {
	txid64 := "abababababababababababababababababababababababababababababababab"
	if got, ok := validateSiteOrigin(txid64 + "_0"); !ok || got != txid64+"_0" {
		t.Errorf("validateSiteOrigin(%s_0) = %q, %v; want %q, true", txid64, got, ok, txid64+"_0")
	}
	if got, ok := validateSiteOrigin(txid64 + "_12"); !ok || got != txid64+"_12" {
		t.Errorf("unexpected result for vout 12: %q, %v", got, ok)
	}
	if got, ok := validateSiteOrigin(strings.ToUpper(txid64) + "_0"); !ok || got != txid64+"_0" {
		t.Errorf("validateSiteOrigin did not lowercase the txid: got %q, %v", got, ok)
	}

	bad := []string{
		"",
		txid64,             // no vout
		txid64[:63] + "_0", // 63 hex chars
		txid64 + "x_0",     // 65 hex chars
		txid64 + "_",       // no vout digits
		txid64 + "_-1",     // negative
		"nothex" + txid64[6:] + "_0",
	}
	for _, o := range bad {
		if _, ok := validateSiteOrigin(o); ok {
			t.Errorf("validateSiteOrigin(%q) = valid, want invalid", o)
		}
	}
}

func TestLooksLikeOutpoint(t *testing.T) {
	txid64 := "abababababababababababababababababababababababababababababababab"
	if !looksLikeOutpoint(txid64 + "_0") {
		t.Errorf("looksLikeOutpoint(%s_0) = false, want true", txid64)
	}
	if looksLikeOutpoint("example.com") {
		t.Error("looksLikeOutpoint(example.com) = true, want false")
	}
}

func TestParseSiteArg(t *testing.T) {
	txid64 := "abababababababababababababababababababababababababababababababab"

	entry, err := parseSiteArg("example.com")
	if err != nil || entry.Kind != "domain" || entry.Value != "example.com" {
		t.Errorf("parseSiteArg(example.com) = %+v, %v", entry, err)
	}

	entry, err = parseSiteArg(txid64 + "_0")
	if err != nil || entry.Kind != "origin" || entry.Value != txid64+"_0" {
		t.Errorf("parseSiteArg(origin) = %+v, %v", entry, err)
	}

	if _, err := parseSiteArg("not a domain!!"); err == nil {
		t.Error("parseSiteArg(invalid) succeeded, want error")
	}
	if _, err := parseSiteArg(txid64 + "_notanumber"); err == nil {
		t.Error("parseSiteArg with a non-outpoint-shaped underscore arg should fall through to domain validation and fail")
	}
}

func TestReadSiteEntries(t *testing.T) {
	dir := t.TempDir()

	t.Run("missing file is empty, not an error", func(t *testing.T) {
		entries, err := readSiteEntries(filepath.Join(dir, "nope.conf"))
		if err != nil || entries != nil {
			t.Errorf("readSiteEntries(missing) = %v, %v; want nil, nil", entries, err)
		}
	})

	txid64 := "abababababababababababababababababababababababababababababababab"
	content := "# a comment\n\ndomain example.com\norigin " + txid64 + "_0\nDOMAIN Second.example\nmalformed line with too many fields\nbogus-keyword example.com\n"
	path := filepath.Join(dir, "sites.conf")
	if err := os.WriteFile(path, []byte(content), 0640); err != nil {
		t.Fatal(err)
	}

	entries, err := readSiteEntries(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []siteEntry{
		{Kind: "domain", Value: "example.com"},
		{Kind: "origin", Value: txid64 + "_0"},
		{Kind: "domain", Value: "second.example"},
	}
	if len(entries) != len(want) {
		t.Fatalf("got %d entries, want %d: %+v", len(entries), len(want), entries)
	}
	for i := range want {
		if entries[i] != want[i] {
			t.Errorf("entry %d = %+v, want %+v", i, entries[i], want[i])
		}
	}
}

func TestAddSiteEntry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sites.conf")

	t.Run("creates a missing file", func(t *testing.T) {
		if err := addSiteEntry(path, siteEntry{Kind: "domain", Value: "example.com"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		entries, _ := readSiteEntries(path)
		if len(entries) != 1 || entries[0].Value != "example.com" {
			t.Fatalf("unexpected entries after create: %+v", entries)
		}
	})

	t.Run("preserves existing content and appends", func(t *testing.T) {
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := addSiteEntry(path, siteEntry{Kind: "domain", Value: "second.example"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		after, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(after)[:len(before)] != string(before) {
			t.Errorf("addSiteEntry did not preserve existing content verbatim.\nbefore:\n%s\nafter:\n%s", before, after)
		}
		entries, _ := readSiteEntries(path)
		if len(entries) != 2 {
			t.Fatalf("expected 2 entries, got %+v", entries)
		}
	})

	t.Run("is idempotent — rejects a duplicate", func(t *testing.T) {
		if err := addSiteEntry(path, siteEntry{Kind: "domain", Value: "example.com"}); err == nil {
			t.Error("addSiteEntry of a duplicate succeeded, want an error")
		}
	})

	t.Run("writes with mode 0640", func(t *testing.T) {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0640 {
			t.Errorf("sites file mode = %v, want 0640", info.Mode().Perm())
		}
	})
}

func TestRemoveSiteEntry(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sites.conf")
	const original = "# keep me\ndomain example.com\ndomain second.example\n"
	if err := os.WriteFile(path, []byte(original), 0640); err != nil {
		t.Fatal(err)
	}

	t.Run("missing file reports not-removed, no error", func(t *testing.T) {
		removed, err := removeSiteEntry(filepath.Join(dir, "nope.conf"), siteEntry{Kind: "domain", Value: "example.com"})
		if err != nil || removed {
			t.Errorf("removeSiteEntry(missing file) = %v, %v; want false, nil", removed, err)
		}
	})

	t.Run("entry not present reports not-removed", func(t *testing.T) {
		removed, err := removeSiteEntry(path, siteEntry{Kind: "domain", Value: "third.example"})
		if err != nil || removed {
			t.Errorf("removeSiteEntry(absent) = %v, %v; want false, nil", removed, err)
		}
	})

	t.Run("removes the matching line, keeps the comment and the other entry", func(t *testing.T) {
		removed, err := removeSiteEntry(path, siteEntry{Kind: "domain", Value: "example.com"})
		if err != nil || !removed {
			t.Fatalf("removeSiteEntry = %v, %v; want true, nil", removed, err)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		got := string(data)
		if !containsLine(got, "# keep me") {
			t.Errorf("removeSiteEntry dropped the comment line:\n%s", got)
		}
		if !containsLine(got, "domain second.example") {
			t.Errorf("removeSiteEntry dropped the unrelated entry:\n%s", got)
		}
		if containsLine(got, "domain example.com") {
			t.Errorf("removeSiteEntry left the removed entry in place:\n%s", got)
		}
	})
}

func containsLine(text, line string) bool {
	for _, l := range splitLinesForTest(text) {
		if l == line {
			return true
		}
	}
	return false
}

func splitLinesForTest(text string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(text); i++ {
		if text[i] == '\n' {
			lines = append(lines, text[start:i])
			start = i + 1
		}
	}
	if start < len(text) {
		lines = append(lines, text[start:])
	}
	return lines
}

func TestMatchesSiteEntry(t *testing.T) {
	entry := siteEntry{Kind: "domain", Value: "example.com"}
	cases := map[string]bool{
		"domain example.com":   true,
		"DOMAIN Example.com":   true,
		"domain other.example": false,
		"origin example.com":   false,
		"# domain example.com": false,
		"":                     false,
		"domain":               false,
	}
	for line, want := range cases {
		if got := matchesSiteEntry(line, entry); got != want {
			t.Errorf("matchesSiteEntry(%q, %+v) = %v, want %v", line, entry, got, want)
		}
	}
}

func TestWriteSitesFileAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sites.conf")
	if err := writeSitesFileAtomic(path, "domain example.com\n"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "domain example.com\n" {
		t.Errorf("unexpected content: %q", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0640 {
		t.Errorf("mode = %v, want 0640", info.Mode().Perm())
	}
	if _, err := os.Stat(path + ".new"); !os.IsNotExist(err) {
		t.Errorf("staging file %s.new was left behind", path)
	}
}
