package lookups

// This file covers the fix pass's ls_uhrp query-key port (spec item 5 /
// cold review RISKS: "Lookup query differences from canonical. Canonical
// supports {outpoint}, {hostIdentityKey} and {expiryTime} and filters by
// every key supplied. ... Not flagged."). UHRPLookupQuery
// (topics/uhrp_lookup.go) and uhrpQueryFilter (uhrp_filter.go) gained
// these three keys, but had no dedicated test before this file — the
// gap the review's wording above describes.

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
)

func lookupQ(t *testing.T, s *UHRPLookupService, q topics.UHRPLookupQuery) *lookup.LookupAnswer {
	t.Helper()
	body, err := json.Marshal(q)
	if err != nil {
		t.Fatalf("marshal query: %v", err)
	}
	answer, err := s.Lookup(ctxBg(), &lookup.LookupQuestion{Service: topics.UHRPLookupServiceName, Query: body})
	if err != nil {
		t.Fatalf("lookup %+v: %v", q, err)
	}
	return answer
}

// TestUHRP_LookupByOutpoint proves the Outpoint query key (canonical's
// direct single-record lookup, "<txid-hex>.<index>") resolves exactly the
// admitted record, and that it short-circuits ahead of every other key —
// matching canonical UHRPLookupService.ts's lookup(), which returns on
// this path before even inspecting the rest of the query object. A
// deliberately wrong ContentHash is included in the same query to prove
// it is ignored, not just absent.
func TestUHRP_LookupByOutpoint(t *testing.T) {
	s := newUHRPLookup(t)
	hash := freshUHRPHash(0x90)
	idPub := freshIdentityPub(t)
	payload := buildUHRPBRC26AdmitPayload(t, idPub, hash, "https://outpoint.example.com/x", 2000000000, 10)
	if err := s.OutputAdmittedByTopic(ctxBg(), payload); err != nil {
		t.Fatalf("admit: %v", err)
	}
	op := mustOutpointFromPayload(t, payload)
	outpointStr := fmt.Sprintf("%s.%d", op.Txid.String(), op.Index)

	answer := lookupQ(t, s, topics.UHRPLookupQuery{Outpoint: outpointStr, ContentHash: sampleHashB})
	if answer.Type != lookup.AnswerTypeFormula || len(answer.Formulas) != 1 {
		t.Fatalf("expected 1 formula ignoring the mismatched content_hash, got type=%s n=%d", answer.Type, len(answer.Formulas))
	}
	if got := answer.Formulas[0].Outpoint; got == nil || !got.Equal(op) {
		t.Fatalf("outpoint mismatch: got %v want %v", got, op)
	}
}

// TestUHRP_LookupByOutpointMissingReturnsEmpty proves a well-formed but
// never-admitted outpoint resolves to an empty formula list, not an
// error — the same "absent means empty" contract every other UHRP query
// shape already has.
func TestUHRP_LookupByOutpointMissingReturnsEmpty(t *testing.T) {
	s := newUHRPLookup(t)
	answer := lookupQ(t, s, topics.UHRPLookupQuery{Outpoint: strings.Repeat("00", 32) + ".0"})
	if answer.Type != lookup.AnswerTypeFormula || len(answer.Formulas) != 0 {
		t.Fatalf("expected 0 formulas for a missing outpoint, got type=%s n=%d", answer.Type, len(answer.Formulas))
	}
}

// TestUHRP_LookupByOutpointMalformedErrors proves a malformed Outpoint
// string (missing the "." separator parseUHRPOutpointQuery requires) is a
// clean error, not a silent empty result or a panic.
func TestUHRP_LookupByOutpointMalformedErrors(t *testing.T) {
	s := newUHRPLookup(t)
	q, _ := json.Marshal(topics.UHRPLookupQuery{Outpoint: "not-an-outpoint"})
	if _, err := s.Lookup(ctxBg(), &lookup.LookupQuestion{Service: topics.UHRPLookupServiceName, Query: q}); err == nil {
		t.Fatalf("expected an error for a malformed outpoint")
	}
}

// TestUHRP_HostIdentityKeyAndExpiryTimeANDCombine proves HostIdentityKey
// and ExpiryTime AND-combine with a content_hash base set (and, supplied
// alone, trigger a full scan) the same way canonical UHRPLookupService.ts's
// `records.find(query)` Mongo-style multi-field exact match does. Two
// BRC-26 adverts for the SAME content hash, from two different hosts with
// two different expiries, are the fixture — the realistic shape this
// filter exists for (multiple hosts serving one file).
func TestUHRP_HostIdentityKeyAndExpiryTimeANDCombine(t *testing.T) {
	s := newUHRPLookup(t)
	hash := freshUHRPHash(0x91)
	idA, idB := freshIdentityPub(t), freshIdentityPub(t)
	const expiryA, expiryB = 2000000000, 3000000000

	payloadA := buildUHRPBRC26AdmitPayload(t, idA, hash, "https://host-a.example.com/x", expiryA, 10)
	payloadB := buildUHRPBRC26AdmitPayload(t, idB, hash, "https://host-b.example.com/x", expiryB, 20)
	if err := s.OutputAdmittedByTopic(ctxBg(), payloadA); err != nil {
		t.Fatalf("admit A: %v", err)
	}
	if err := s.OutputAdmittedByTopic(ctxBg(), payloadB); err != nil {
		t.Fatalf("admit B: %v", err)
	}
	opA := mustOutpointFromPayload(t, payloadA)
	hashHex := hex.EncodeToString(hash)
	idAHex := hex.EncodeToString(idA)

	// Base set alone: both hosts.
	if answer := lookupQ(t, s, topics.UHRPLookupQuery{ContentHash: hashHex}); len(answer.Formulas) != 2 {
		t.Fatalf("content_hash alone: expected 2 formulas, got %d", len(answer.Formulas))
	}

	// content_hash + hostIdentityKey narrows to host A only.
	narrowed := lookupQ(t, s, topics.UHRPLookupQuery{ContentHash: hashHex, HostIdentityKey: idAHex})
	if len(narrowed.Formulas) != 1 || !narrowed.Formulas[0].Outpoint.Equal(opA) {
		t.Fatalf("content_hash+hostIdentityKey: expected only host A's outpoint, got %+v", narrowed.Formulas)
	}

	// Case-insensitive match (canonical hex comparison, not case-sensitive).
	upper := lookupQ(t, s, topics.UHRPLookupQuery{ContentHash: hashHex, HostIdentityKey: strings.ToUpper(idAHex)})
	if len(upper.Formulas) != 1 {
		t.Fatalf("uppercased hostIdentityKey: expected a case-insensitive match, got %d formulas", len(upper.Formulas))
	}

	// content_hash + expiryTime narrows to the one matching advert.
	byExpiry := lookupQ(t, s, topics.UHRPLookupQuery{ContentHash: hashHex, ExpiryTime: expiryA})
	if len(byExpiry.Formulas) != 1 || !byExpiry.Formulas[0].Outpoint.Equal(opA) {
		t.Fatalf("content_hash+expiryTime: expected only host A's outpoint, got %+v", byExpiry.Formulas)
	}

	// hostIdentityKey alone (no hash, no list) triggers a full scan, same
	// as List:"all" would, narrowed by the filter.
	aloneAnswer := lookupQ(t, s, topics.UHRPLookupQuery{HostIdentityKey: idAHex})
	if len(aloneAnswer.Formulas) != 1 || !aloneAnswer.Formulas[0].Outpoint.Equal(opA) {
		t.Fatalf("hostIdentityKey alone: expected a full-scan match on host A only, got %+v", aloneAnswer.Formulas)
	}

	// An unknown identity key narrows to nothing, not an error.
	none := lookupQ(t, s, topics.UHRPLookupQuery{ContentHash: hashHex, HostIdentityKey: hex.EncodeToString(freshIdentityPub(t))})
	if len(none.Formulas) != 0 {
		t.Fatalf("unknown hostIdentityKey: expected 0 formulas, got %d", len(none.Formulas))
	}
}
