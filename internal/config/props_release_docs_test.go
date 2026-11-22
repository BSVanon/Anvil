package config

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var errorCodePattern = regexp.MustCompile(`ERR_[A-Z0-9_]+`)

func TestDocumentedErrorCodesExactlyMatchCode(t *testing.T) {
	root := filepath.Join("..", "..")
	code := make(map[string]bool)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// Skip hidden directories (version control, editor and tool state).
		if entry.IsDir() && path != root && strings.HasPrefix(entry.Name(), ".") {
			return filepath.SkipDir
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, match := range errorCodePattern.FindAllString(string(data), -1) {
			code[match] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	documented := documentedErrorCodes(t, root)
	if missing := setDifference(code, documented); len(missing) != 0 {
		t.Errorf("error codes missing from documentation: %v", missing)
	}
	if stale := setDifference(documented, code); len(stale) != 0 {
		t.Errorf("documented error codes absent from code: %v", stale)
	}
}

func documentedErrorCodes(t *testing.T, root string) map[string]bool {
	t.Helper()
	got := make(map[string]bool)
	paths := []string{filepath.Join(root, "docs", "API_REFERENCE.md"), filepath.Join(root, "docs", "PAYMENTS.md")}
	operator := filepath.Join(root, "docs", "operator")
	entries, err := os.ReadDir(operator)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".md") {
			paths = append(paths, filepath.Join(operator, entry.Name()))
		}
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range errorCodePattern.FindAllString(string(data), -1) {
			got[match] = true
		}
	}
	return got
}

func TestEveryAcceptedTOMLKeyIsInExampleOrExplained(t *testing.T) {
	accepted := make(map[string]bool)
	collectTOMLKeys(reflect.TypeOf(Config{}), "", accepted)
	example := exampleTOMLKeys(t, filepath.Join("..", "..", "anvil.example.toml"))
	exceptions := map[string]string{
		"peers.seeds":                        "legacy pre-mesh section retained only for decoding compatibility",
		"foundry.seeds":                      "deprecated alias for mesh seeds",
		"foundry.allowed_peers":              "deprecated foundry alias; only seeds are merged",
		"foundry.min_bond_sats":              "deprecated foundry alias; only seeds are merged",
		"foundry.bond_check_url":             "deprecated foundry alias; only seeds are merged",
		"foundry.local_pubkeys":              "deprecated foundry alias; only seeds are merged",
		"foundry.rate_per_sec":               "deprecated foundry alias; only seeds are merged",
		"foundry.rate_burst":                 "deprecated foundry alias; only seeds are merged",
		"foundry.peer_exchange":              "deprecated foundry alias; only seeds are merged",
		"foundry.advertise_url":              "deprecated foundry alias; only seeds are merged",
		"foundry.max_exchange_peers":         "deprecated foundry alias; only seeds are merged",
		"junglebus.subscriptions":            "retired JungleBus compatibility field; runtime no-op",
		"junglebus.subscriptions.id":         "retired JungleBus compatibility field; runtime no-op",
		"junglebus.subscriptions.name":       "retired JungleBus compatibility field; runtime no-op",
		"junglebus.subscriptions.from_block": "retired JungleBus compatibility field; runtime no-op",
	}
	var missing []string
	for key := range accepted {
		if !example[key] && exceptions[key] == "" {
			missing = append(missing, key)
		}
	}
	sort.Strings(missing)
	if len(missing) != 0 {
		t.Fatalf("accepted TOML keys missing from example and exception table: %v", missing)
	}
}

func collectTOMLKeys(typ reflect.Type, prefix string, out map[string]bool) {
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if field.PkgPath != "" {
			continue
		}
		name := strings.Split(field.Tag.Get("toml"), ",")[0]
		if name == "-" {
			continue
		}
		if name == "" {
			name = strings.ToLower(field.Name)
		}
		path := name
		if prefix != "" {
			path = prefix + "." + name
		}
		fieldType := field.Type
		if fieldType.Kind() == reflect.Pointer {
			fieldType = fieldType.Elem()
		}
		switch fieldType.Kind() {
		case reflect.Struct:
			collectTOMLKeys(fieldType, path, out)
		case reflect.Slice:
			out[path] = true
			if fieldType.Elem().Kind() == reflect.Struct {
				collectTOMLKeys(fieldType.Elem(), path, out)
			}
		default:
			out[path] = true
		}
	}
}

func exampleTOMLKeys(t *testing.T, path string) map[string]bool {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	sectionPattern := regexp.MustCompile(`^\s*#?\s*\[\[?([A-Za-z0-9_.]+)\]?\]\s*(?:#.*)?$`)
	keyPattern := regexp.MustCompile(`^\s*#?\s*([A-Za-z_][A-Za-z0-9_]*)\s*=`)
	section := ""
	keys := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if match := sectionPattern.FindStringSubmatch(line); match != nil {
			section = match[1]
			keys[section] = true
			continue
		}
		if match := keyPattern.FindStringSubmatch(line); match != nil {
			key := match[1]
			if section != "" {
				key = section + "." + key
			}
			keys[key] = true
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return keys
}

func TestReleaseResponseHeadersAreDocumented(t *testing.T) {
	root := filepath.Join("..", "..")
	var docs strings.Builder
	for _, path := range []string{filepath.Join(root, "docs", "API_REFERENCE.md"), filepath.Join(root, "docs", "PAYMENTS.md"), filepath.Join(root, "docs", "operator", "gateway.md")} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		docs.Write(data)
	}
	headers := []string{
		"X-Ord-Seq", "X-Origin", "X-Outpoint",
		"X-Overlay-Cursor", "X-Overlay-Truncated", "X-Overlay-Omitted",
		"X-Overlay-Gasp-Enabled", "X-Overlay-Gasp-Initial-Sync-Done", "X-Overlay-Gasp-Interval-Secs", "X-Overlay-Gasp-Last-Sync-Unix",
		"X-BEEF-Source", "X-BEEF-Subject-Proven",
		"X-Block-Height", "X-Start-Height", "X-Header-Count",
		"X-Accel-Buffering", "X-Content-Type-Options", "x-bsv-sats", "x-bsv-server", "X402-Receipt",
	}
	for _, header := range headers {
		if !strings.Contains(docs.String(), header) {
			t.Errorf("release response header %s is undocumented", header)
		}
	}
}

func setDifference(left, right map[string]bool) []string {
	var out []string
	for value := range left {
		if !right[value] {
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}
