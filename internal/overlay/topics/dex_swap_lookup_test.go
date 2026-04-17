package topics

import (
	"encoding/json"
	"testing"
)

// TestContainsTokenTxid covers the filter logic used by DEXSwapLookupService
// to match offers by their offering/requesting token txid. Case-insensitive
// per strings.EqualFold so callers can query with either lower or mixed case.
func TestContainsTokenTxid(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		txid string
		want bool
	}{
		{
			name: "match",
			raw:  `{"token":{"txid":"abc123"}}`,
			txid: "abc123",
			want: true,
		},
		{
			name: "case insensitive",
			raw:  `{"token":{"txid":"AbC123"}}`,
			txid: "abc123",
			want: true,
		},
		{
			name: "no match",
			raw:  `{"token":{"txid":"abc123"}}`,
			txid: "def456",
			want: false,
		},
		{
			name: "missing token object",
			raw:  `{"kind":"bsv","amount":1000}`,
			txid: "abc123",
			want: false,
		},
		{
			name: "malformed JSON",
			raw:  `not json`,
			txid: "abc123",
			want: false,
		},
		{
			name: "empty raw",
			raw:  ``,
			txid: "abc123",
			want: false,
		},
		{
			name: "null token field",
			raw:  `{"token":null}`,
			txid: "abc123",
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := containsTokenTxid(json.RawMessage(tc.raw), tc.txid)
			if got != tc.want {
				t.Errorf("containsTokenTxid(%q, %q) = %v, want %v", tc.raw, tc.txid, got, tc.want)
			}
		})
	}
}

// TestDEXSwapLookupService_DocMetadata verifies the lookup service advertises
// itself correctly — this is the shape consumers discover via /overlay/services.
func TestDEXSwapLookupService_DocMetadata(t *testing.T) {
	ls := NewDEXSwapLookupService(nil)

	doc := ls.GetDocumentation()
	if doc == "" {
		t.Error("expected non-empty documentation")
	}

	meta := ls.GetMetadata()
	if meta["service"] != DEXSwapLookupServiceName {
		t.Errorf("expected service=%q, got %v", DEXSwapLookupServiceName, meta["service"])
	}
	queries, _ := meta["queries"].([]string)
	expectedQueries := []string{"list", "offering_token_txid", "requesting_token_txid", "maker"}
	if len(queries) != len(expectedQueries) {
		t.Errorf("expected %d query types, got %d", len(expectedQueries), len(queries))
	}
}

// TestDEXSwapLookupService_InvalidQueryReturnsError verifies malformed JSON
// query bodies produce a structured error rather than a nil answer.
func TestDEXSwapLookupService_InvalidQueryReturnsError(t *testing.T) {
	ls := NewDEXSwapLookupService(nil)
	_, err := ls.Lookup(json.RawMessage(`{malformed`))
	if err == nil {
		t.Fatal("expected error on malformed query JSON")
	}
}
