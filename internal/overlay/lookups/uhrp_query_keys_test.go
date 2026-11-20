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
	"github.com/bsv-blockchain/go-sdk/storage"
	"github.com/bsv-blockchain/go-sdk/transaction"
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

// --- re-review fix-pass coverage: BLOCKER (corrupt records) + RISKS items 2/3 ---

// corruptUHRPRecord admits one normal BRC-26 record via s, then overwrites
// its stored item body in place with bytes that fail json.Unmarshal —
// reproducing "a stored record under a directly-queried outpoint that
// fails to JSON-decode" (re-review BLOCKER) without needing a real
// bit-rot event. The hash index entry is left untouched, so the record
// stays reachable by every query shape exactly as a real corruption would
// leave it.
func corruptUHRPRecord(t *testing.T, s *UHRPLookupService, hash []byte, url string, expiry, size uint64) *transaction.Outpoint {
	t.Helper()
	payload := buildUHRPBRC26AdmitPayload(t, freshIdentityPub(t), hash, url, expiry, size)
	if err := s.OutputAdmittedByTopic(ctxBg(), payload); err != nil {
		t.Fatalf("admit: %v", err)
	}
	op := mustOutpointFromPayload(t, payload)
	if err := s.db.Put(uhrpItemKey(&op.Txid, op.Index), []byte("not valid json"), nil); err != nil {
		t.Fatalf("corrupt stored item: %v", err)
	}
	return op
}

// TestUHRP_CorruptRecordSkippedOnEveryQueryShape is the re-review BLOCKER
// fix: lookupByOutpoint used to propagate a corrupt record's JSON-decode
// failure as a hard error, while itemsByHash and allItemRecords (the
// content_hash/uhrpUrl and list=all paths) already skipped the same
// failure with a warn log. All four query shapes that can reach a single
// corrupt record must now treat it identically — an empty answer, never
// an error.
func TestUHRP_CorruptRecordSkippedOnEveryQueryShape(t *testing.T) {
	s := newUHRPLookup(t)
	hash := freshUHRPHash(0xc0)
	op := corruptUHRPRecord(t, s, hash, "https://corrupt.example.com/x", 2000000000, 10)
	hashHex := hex.EncodeToString(hash)
	b58, err := storage.GetURLForHash(hash)
	if err != nil {
		t.Fatalf("GetURLForHash: %v", err)
	}

	outpointStr := fmt.Sprintf("%s.%d", op.Txid.String(), op.Index)
	byOutpoint := lookupQ(t, s, topics.UHRPLookupQuery{Outpoint: outpointStr})
	if byOutpoint.Type != lookup.AnswerTypeFormula || len(byOutpoint.Formulas) != 0 {
		t.Fatalf("by outpoint: expected the corrupt record skipped with an empty answer, got type=%s n=%d", byOutpoint.Type, len(byOutpoint.Formulas))
	}

	byURL := lookupQ(t, s, topics.UHRPLookupQuery{UhrpUrl: "uhrp://" + b58})
	if len(byURL.Formulas) != 0 {
		t.Fatalf("by uhrpUrl: expected the corrupt record skipped, got %d formulas", len(byURL.Formulas))
	}

	byHash := lookupQ(t, s, topics.UHRPLookupQuery{ContentHash: hashHex})
	if len(byHash.Formulas) != 0 {
		t.Fatalf("by content_hash: expected the corrupt record skipped, got %d formulas", len(byHash.Formulas))
	}

	listAll := lookupQ(t, s, topics.UHRPLookupQuery{List: "all"})
	if len(listAll.Formulas) != 0 {
		t.Fatalf("list=all: expected the corrupt record skipped, got %d formulas", len(listAll.Formulas))
	}
}

// TestUHRP_LookupByOutpointIgnoresExpiry is the re-review RISKS item 2
// fix: canonical UHRPLookupService.ts:62-67's outpoint branch is a bare
// findOne with no expiry check at all, so lookupByOutpoint must return an
// expired BRC-26 record too, exactly as canonical would — while every
// other query key keeps filtering it out, the pre-existing, deliberate
// Anvil-only hardening that canonical itself doesn't apply on its own
// non-outpoint path either (UHRPLookupService.ts:68-72's
// records.find(query) has no expiry check server-side; see
// filterUHRPRecords' divergence comment, uhrp_filter.go).
func TestUHRP_LookupByOutpointIgnoresExpiry(t *testing.T) {
	s := newUHRPLookup(t)
	withFixedNow(t, 1000)

	hash := freshUHRPHash(0xc1)
	payload := buildUHRPBRC26AdmitPayload(t, freshIdentityPub(t), hash, "https://expired-outpoint.example.com/x", 500, 10)
	if err := s.OutputAdmittedByTopic(ctxBg(), payload); err != nil {
		t.Fatalf("admit expired: %v", err)
	}
	op := mustOutpointFromPayload(t, payload)
	outpointStr := fmt.Sprintf("%s.%d", op.Txid.String(), op.Index)

	byOutpoint := lookupQ(t, s, topics.UHRPLookupQuery{Outpoint: outpointStr})
	if len(byOutpoint.Formulas) != 1 || !byOutpoint.Formulas[0].Outpoint.Equal(op) {
		t.Fatalf("by outpoint: expected the expired record returned (canonical has no expiry check here), got %+v", byOutpoint.Formulas)
	}

	byHash := lookupQ(t, s, topics.UHRPLookupQuery{ContentHash: hex.EncodeToString(hash)})
	if len(byHash.Formulas) != 0 {
		t.Fatalf("by content_hash: expected the expired record still filtered (Anvil's own stricter, pre-existing choice), got %d formulas", len(byHash.Formulas))
	}

	listAll := lookupQ(t, s, topics.UHRPLookupQuery{List: "all"})
	if len(listAll.Formulas) != 0 {
		t.Fatalf("list=all: expected the expired record still filtered, got %d formulas", len(listAll.Formulas))
	}
}

// TestUHRP_HostIdentityKeyMatchIsCaseInsensitive pins the deliberate
// divergence documented on uhrpQueryFilter.matches (uhrp_filter.go,
// re-review RISKS item 3): canonical UHRPLookupService.ts matches
// hostIdentityKey case-sensitively against lowercase hex, Anvil matches
// with strings.EqualFold. A query in a case that differs from the stored
// (always-lowercase, hex.EncodeToString-produced) identity key must still
// match.
func TestUHRP_HostIdentityKeyMatchIsCaseInsensitive(t *testing.T) {
	s := newUHRPLookup(t)
	hash := freshUHRPHash(0xc2)
	idPub := freshIdentityPub(t)
	payload := buildUHRPBRC26AdmitPayload(t, idPub, hash, "https://case.example.com/x", 2000000000, 10)
	if err := s.OutputAdmittedByTopic(ctxBg(), payload); err != nil {
		t.Fatalf("admit: %v", err)
	}
	op := mustOutpointFromPayload(t, payload)
	idHex := hex.EncodeToString(idPub)

	for _, variant := range []string{idHex, strings.ToUpper(idHex)} {
		answer := lookupQ(t, s, topics.UHRPLookupQuery{HostIdentityKey: variant})
		if len(answer.Formulas) != 1 || !answer.Formulas[0].Outpoint.Equal(op) {
			t.Fatalf("hostIdentityKey %q: expected a case-insensitive match, got %+v", variant, answer.Formulas)
		}
	}
}

// TestUHRP_ExpiryTimeMatchIsExactNotRange pins expiryTime's documented
// semantics (uhrpQueryFilter.matches, uhrp_filter.go): a strict equality
// comparison, matching canonical UHRPLookupService.ts:71's
// `records.find(query)` exactly — never a >=/<= range. Two adverts with
// well-separated expiries prove a query for a third value, equal to
// neither, matches nothing — a range comparison would wrongly catch one
// (or both) of them here.
func TestUHRP_ExpiryTimeMatchIsExactNotRange(t *testing.T) {
	s := newUHRPLookup(t)
	hash := freshUHRPHash(0xc3)
	const expiryLow, expiryMid, expiryHigh = 2000000000, 2500000000, 3000000000

	payloadLow := buildUHRPBRC26AdmitPayload(t, freshIdentityPub(t), hash, "https://exact-low.example.com/x", expiryLow, 10)
	payloadHigh := buildUHRPBRC26AdmitPayload(t, freshIdentityPub(t), hash, "https://exact-high.example.com/x", expiryHigh, 10)
	if err := s.OutputAdmittedByTopic(ctxBg(), payloadLow); err != nil {
		t.Fatalf("admit low: %v", err)
	}
	if err := s.OutputAdmittedByTopic(ctxBg(), payloadHigh); err != nil {
		t.Fatalf("admit high: %v", err)
	}
	opLow := mustOutpointFromPayload(t, payloadLow)
	opHigh := mustOutpointFromPayload(t, payloadHigh)
	hashHex := hex.EncodeToString(hash)

	low := lookupQ(t, s, topics.UHRPLookupQuery{ContentHash: hashHex, ExpiryTime: expiryLow})
	if len(low.Formulas) != 1 || !low.Formulas[0].Outpoint.Equal(opLow) {
		t.Fatalf("expiryTime=%d: expected only the exact-match advert, got %+v", expiryLow, low.Formulas)
	}

	high := lookupQ(t, s, topics.UHRPLookupQuery{ContentHash: hashHex, ExpiryTime: expiryHigh})
	if len(high.Formulas) != 1 || !high.Formulas[0].Outpoint.Equal(opHigh) {
		t.Fatalf("expiryTime=%d: expected only the exact-match advert, got %+v", expiryHigh, high.Formulas)
	}

	mid := lookupQ(t, s, topics.UHRPLookupQuery{ContentHash: hashHex, ExpiryTime: expiryMid})
	if len(mid.Formulas) != 0 {
		t.Fatalf("expiryTime=%d (between both, equal to neither): expected 0 formulas, got %+v", expiryMid, mid.Formulas)
	}
}
