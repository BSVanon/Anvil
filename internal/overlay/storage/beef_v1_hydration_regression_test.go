package storage

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BSVanon/Anvil/internal/beefnorm"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// TestBeefV1RoundtripHydration uses a real 4-transaction UMP submit from a
// wallet restore:
// (AtomicBEEF wrapping a V1 BEEF, a 3-deep unconfirmed chain anchored to a
// BUMP) admits fine, but go-sdk's V1 re-serialisation of the parsed BEEF could
// not be re-parsed on hydration — it PANICKED ("index out of range … length 1")
// — so the token was indexed yet silently dropped from lookup results (empty
// result for an existing token). storableBeefBytes persists V2, which
// round-trips; hydration must succeed and preserve the subject output script.
func TestBeefV1RoundtripHydration(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "ump_v1_roundtrip.hex"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	submitted, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("hex: %v", err)
	}

	// Admission path (version-aware) — succeeds, as it did live.
	beef, _, subjectTxid, err := transaction.ParseBeef(submitted)
	if err != nil {
		t.Fatalf("ParseBeef(submitted): %v", err)
	}
	origSubject := beef.FindTransaction(subjectTxid.String())
	if origSubject == nil {
		t.Fatal("subject tx missing from submitted BEEF")
	}
	origScript := hex.EncodeToString(origSubject.Outputs[0].LockingScript.Bytes())

	// Guard: the OLD store path (beef.Bytes(), V1) still panics its own parser —
	// this locks in that the bug is real and that the fix is what avoids it.
	oldStored, err := beef.Bytes()
	if err != nil {
		t.Fatalf("beef.Bytes(): %v", err)
	}
	if _, perr := safeNewBeefFromBytes(oldStored); perr == nil {
		t.Log("note: go-sdk V1 round-trip no longer panics on this fixture (upstream fixed?) — fix still correct")
	}

	// Fix: store via storableBeefBytes (V2), hydrate — MUST succeed.
	stored, err := storableBeefBytes(beef)
	if err != nil {
		t.Fatalf("storableBeefBytes: %v", err)
	}
	hyd, perr := safeNewBeefFromBytes(stored)
	if perr != nil {
		t.Fatalf("hydration of stored BEEF failed after fix: %v", perr)
	}

	// Data preserved: same tx set, subject present, output#0 script identical.
	if len(hyd.Transactions) != len(beef.Transactions) {
		t.Fatalf("tx count changed: stored %d, hydrated %d", len(beef.Transactions), len(hyd.Transactions))
	}
	hydSubject := hyd.FindTransaction(subjectTxid.String())
	if hydSubject == nil {
		t.Fatal("subject tx lost in store->hydrate round-trip")
	}
	if got := hex.EncodeToString(hydSubject.Outputs[0].LockingScript.Bytes()); got != origScript {
		t.Fatalf("subject output#0 script changed across round-trip\n orig=%s\n got =%s", origScript, got)
	}
}

// TestLoadAncillaryBeef_SkipsUnparseableAncillaryBlob: an ancillary BEEF blob
// that does not parse is skipped, never a crash and never a failed load:
// go-overlay-services fails the whole lookup answer when LoadAncillaryBeef
// returns an error. The blob is testdata/ump_v1_legacy_malformed.hex: what
// go-sdk v1.2.x's beef.Bytes() wrote for that fixture, a V1 header
// (0100beef) followed by V2-layout transaction entries (format byte before
// each raw tx). Pre-v3.2.14 nodes stored blobs in that shape. v1.2.x panicked
// re-parsing it ("index out of range"); go-sdk v1.7 returns an ordinary error
// ("invalid BEEF transaction hasBump value"). The blob is a fixture now because
// v1.7's beef.Bytes() writes the V1 layout correctly, so re-serializing no
// longer reproduces it. A good ancillary alongside the bad one checks that
// skipping it does not also skip the rest: nothing that does not parse can be
// fixed by normalizing it, so
// this is the one skip-but-keep-going case normalizing stored BEEFs cannot
// make go away.
func TestLoadAncillaryBeef_SkipsUnparseableAncillaryBlob(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "ump_v1_roundtrip.hex"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	submitted, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	beef, _, subjectTxid, err := transaction.ParseBeef(submitted)
	if err != nil {
		t.Fatalf("ParseBeef(submitted): %v", err)
	}
	legacyRaw, err := os.ReadFile(filepath.Join("testdata", "ump_v1_legacy_malformed.hex"))
	if err != nil {
		t.Fatalf("read legacy fixture: %v", err)
	}
	oldStored, err := hex.DecodeString(strings.TrimSpace(string(legacyRaw)))
	if err != nil {
		t.Fatalf("legacy hex: %v", err)
	}

	_, db := newStore(t)
	badAncillaryTxid := makeHash(0xA5)
	if err := db.Put(beefKey(badAncillaryTxid), oldStored, nil); err != nil {
		t.Fatalf("put bad ancillary beef: %v", err)
	}
	honest := minedTx(0x42, 1)
	honest.MerklePath = soleTxBUMP(honest, 7)
	honestBeef, err := transaction.NewBeefFromTransaction(honest)
	if err != nil {
		t.Fatalf("honest ancillary BEEF: %v", err)
	}
	honestBytes, err := storableBeefBytes(honestBeef)
	if err != nil {
		t.Fatalf("serialise honest ancillary: %v", err)
	}
	if err := db.Put(beefKey(honest.TxID()), honestBytes, nil); err != nil {
		t.Fatalf("put honest ancillary beef: %v", err)
	}

	out := &engine.Output{
		Outpoint: transaction.Outpoint{Txid: *subjectTxid, Index: 0},
		Beef:     beef,
	}
	out.AncillaryTxids = append(out.AncillaryTxids, badAncillaryTxid, honest.TxID())
	txs := len(beef.Transactions)

	if err := New(db).LoadAncillaryBeef(ctxBg(), out); err != nil {
		t.Fatalf("an unparseable ancillary BEEF failed the load: %v", err)
	}
	// MergeBeef mutates its receiver in place, so a successful merge of the
	// honest ancillary leaves out.Beef pointer-identical to beef; only a
	// rebuild after a merge panic would swap in a different pointer.
	if out.Beef != beef || len(out.Beef.Transactions) != txs+1 || out.Beef.FindTransaction(subjectTxid.String()) == nil {
		t.Fatal("skipping the unparseable ancillary also skipped the good one, or changed the subject")
	}
	if out.Beef.FindTransactionByHash(honest.TxID()) == nil {
		t.Fatal("the honest ancillary alongside the bad one did not merge")
	}

	target := beef
	m, err := newAncillaryMerge(&target)
	if err != nil {
		t.Fatal(err)
	}
	err = m.merge(oldStored)
	if err == nil || !errors.Is(err, beefnorm.ErrRefused) {
		t.Fatalf("expected the legacy layout refused as unparseable, got: %v", err)
	}
	if strings.Contains(err.Error(), "panicked") {
		t.Fatalf("go-sdk should reject the legacy layout with an error, not a recovered panic: %v", err)
	}
	if target != beef {
		t.Fatal("a blob that does not parse replaced the target BEEF")
	}
}
