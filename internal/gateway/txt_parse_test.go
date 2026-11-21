package gateway

import (
	"strings"
	"testing"
)

// TestParseOrdfsTXT is a parsing table: valid, case, spaces,
// multiple strings (already concatenated by Go's resolver before this
// function sees them — represented here as one record string), duplicate
// records, conflicting values, bad txid or vout, missing.
func TestParseOrdfsTXT(t *testing.T) {
	const txid = "a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718a1b2c3d4e5f60718" // 64 hex chars
	const outpoint = txid + "_0"

	tests := []struct {
		name       string
		records    []string
		wantOrigin string
		wantOK     bool
	}{
		{
			name:       "valid",
			records:    []string{"ordfs=" + outpoint},
			wantOrigin: outpoint,
			wantOK:     true,
		},
		{
			name:       "uppercase key",
			records:    []string{"ORDFS=" + outpoint},
			wantOrigin: outpoint,
			wantOK:     true,
		},
		{
			name:       "mixed case key",
			records:    []string{"OrdFs=" + outpoint},
			wantOrigin: outpoint,
			wantOK:     true,
		},
		{
			name:       "surrounding spaces",
			records:    []string{"  ordfs=" + outpoint + "  "},
			wantOrigin: outpoint,
			wantOK:     true,
		},
		{
			name:       "spaces around key and value",
			records:    []string{" ordfs = " + outpoint},
			wantOrigin: outpoint,
			wantOK:     true,
		},
		{
			name:       "uppercase txid normalised to lowercase",
			records:    []string{"ordfs=" + strings.ToUpper(txid) + "_0"},
			wantOrigin: outpoint,
			wantOK:     true,
		},
		{
			name:       "multiple character-strings already joined by the resolver",
			records:    []string{"ordfs=" + outpoint}, // represents net.LookupTXT already having concatenated the record's strings
			wantOrigin: outpoint,
			wantOK:     true,
		},
		{
			name:       "duplicate records, same value",
			records:    []string{"ordfs=" + outpoint, "ordfs=" + outpoint},
			wantOrigin: outpoint,
			wantOK:     true,
		},
		{
			name:       "conflicting values",
			records:    []string{"ordfs=" + outpoint, "ordfs=" + txid + "_1"},
			wantOrigin: "",
			wantOK:     false,
		},
		{
			name:       "bad txid (too short)",
			records:    []string{"ordfs=abc123_0"},
			wantOrigin: "",
			wantOK:     false,
		},
		{
			name:       "bad txid (non-hex)",
			records:    []string{"ordfs=" + "zz" + txid[2:] + "_0"},
			wantOrigin: "",
			wantOK:     false,
		},
		{
			name:       "bad vout (not decimal)",
			records:    []string{"ordfs=" + txid + "_abc"},
			wantOrigin: "",
			wantOK:     false,
		},
		{
			name:       "bad vout (overflows uint32)",
			records:    []string{"ordfs=" + txid + "_4294967296"},
			wantOrigin: "",
			wantOK:     false,
		},
		{
			name:       "vout at uint32 max is valid",
			records:    []string{"ordfs=" + txid + "_4294967295"},
			wantOrigin: txid + "_4294967295",
			wantOK:     true,
		},
		{
			name:       "missing (no records)",
			records:    nil,
			wantOrigin: "",
			wantOK:     false,
		},
		{
			name:       "missing (unrelated record)",
			records:    []string{"v=spf1 -all"},
			wantOrigin: "",
			wantOK:     false,
		},
		{
			name:       "missing (no equals sign)",
			records:    []string{"ordfs"},
			wantOrigin: "",
			wantOK:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			origin, ok := parseOrdfsTXT(tt.records)
			if ok != tt.wantOK || origin != tt.wantOrigin {
				t.Fatalf("parseOrdfsTXT(%v) = (%q, %v), want (%q, %v)", tt.records, origin, ok, tt.wantOrigin, tt.wantOK)
			}
		})
	}
}
