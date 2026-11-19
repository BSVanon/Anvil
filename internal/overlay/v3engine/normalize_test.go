package v3engine

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/beefnorm/beefnormtest"
	"github.com/BSVanon/Anvil/internal/headers"
	"github.com/BSVanon/Anvil/internal/overlay/hostiletest"
	"github.com/BSVanon/Anvil/internal/overlay/overlaytest"
	"github.com/BSVanon/Anvil/internal/overlay/routeguard"
	anvilstorage "github.com/BSVanon/Anvil/internal/overlay/storage"
	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	p2pchainhash "github.com/libsv/go-p2p/chaincfg/chainhash"
	"github.com/libsv/go-p2p/wire"
	"github.com/syndtr/goleveldb/leveldb"
)

// normEngine is newTestEngine's engine, served under a guard of its own, with
// its headers store, to which a test adds the block its proofs are in.
func normEngine(t *testing.T) (*engine.Engine, *headers.Store, string) {
	t.Helper()
	root := t.TempDir()
	var dbs [2]*leveldb.DB
	for i, name := range []string{"storage", "lookup"} {
		db, err := leveldb.OpenFile(filepath.Join(root, name), nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		dbs[i] = db
	}
	hs, err := headers.NewTestStore(filepath.Join(root, "headers"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = hs.Close() })
	overlaytest.SeedFundingBlock(t, hs)
	eng, err := New(&Config{Storage: anvilstorage.New(dbs[0]), HeadersStore: hs, LookupDB: dbs[1], HostingURL: "https://anvil.test"})
	if err != nil {
		t.Fatal(err)
	}
	return eng, hs, guardedServer(t, eng, freshGuard(routeguard.CPUSlots))
}

// addBlock adds the block after the funding block, whose merkle root is root.
func addBlock(t *testing.T, hs *headers.Store, root *chainhash.Hash) uint32 {
	t.Helper()
	prev, err := hs.HashAtHeight(overlaytest.FundingHeight)
	if err != nil {
		t.Fatal(err)
	}
	r := p2pchainhash.Hash(*root)
	if err := hs.AddHeaders(overlaytest.FundingHeight+1, []*wire.BlockHeader{wire.NewBlockHeader(1, prev, &r, 0x1d00ffff, 0)}); err != nil {
		t.Fatal(err)
	}
	return overlaytest.FundingHeight + 1
}

// storedBEEF is the BEEF the engine stored with output 0 of txid for tm_uhrp.
func storedBEEF(t *testing.T, eng *engine.Engine, txid *chainhash.Hash) *transaction.Beef {
	t.Helper()
	topic := topics.UHRPTopicName
	out, err := eng.Storage.FindOutput(context.Background(), &transaction.Outpoint{Txid: *txid, Index: 0}, &topic, nil, true)
	if err != nil || out == nil || out.Beef == nil {
		t.Fatalf("output 0 of %s: %v", txid, err)
	}
	return out.Beef
}

// lookupUHRP asks ls_uhrp for hashHex and returns the status and the BEEF of
// each output answered; aggregated asks for the binary answer, whose BEEFs
// it does not decode.
func lookupUHRP(t *testing.T, url, hashHex string, aggregated bool) (int, []*transaction.Beef) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url+"/lookup", strings.NewReader(`{"service":"ls_uhrp","query":{"content_hash":"`+hashHex+`"}}`))
	req.Header.Set("Content-Type", "application/json")
	if aggregated {
		req.Header.Set("x-aggregation", "yes")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if aggregated || resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil
	}
	var answer struct {
		Outputs []struct {
			Beef []byte `json:"beef"`
		} `json:"outputs"`
	}
	if err := json.Unmarshal(raw, &answer); err != nil {
		t.Fatalf("lookup answer %s: %v", raw, err)
	}
	var beefs []*transaction.Beef
	for _, o := range answer.Outputs {
		b, _, _, err := transaction.ParseBeef(o.Beef)
		if err != nil {
			t.Fatalf("lookup answer BEEF: %v", err)
		}
		beefs = append(beefs, b)
	}
	return resp.StatusCode, beefs
}

// efSpendBEEF is a V2 BEEF of one transaction in extended format whose only
// input spends an output, locked by lock, of a transaction the BEEF does not
// hold: only the extended format supplies it.
func efSpendBEEF(t *testing.T, lock []byte) []byte {
	t.Helper()
	prev := chainhash.DoubleHashH([]byte("an output no BEEF holds"))
	tx := transaction.NewTransaction()
	tx.AddInput(&transaction.TransactionInput{SourceTXID: &prev, UnlockingScript: &script.Script{}, SequenceNumber: transaction.DefaultSequenceNumber})
	ls := script.Script(lock)
	tx.Inputs[0].SetSourceTxOutput(&transaction.TransactionOutput{Satoshis: 10_000, LockingScript: &ls})
	tx.AddOutput(&transaction.TransactionOutput{LockingScript: beefnormtest.Lock(), Satoshis: 1000})
	ef, err := tx.EF()
	if err != nil {
		t.Fatal(err)
	}
	b := binary.LittleEndian.AppendUint32(nil, transaction.BEEF_V2)
	b = append(b, 0, 1, 0) // no BUMPs, one raw transaction
	return append(b, ef...)
}

// TestSubmit_StoresOnlyTheSubjectsGraph: an Atomic BEEF holding a transaction
// outside its subject's graph, as ts-sdk 2.1.0's Beef.getBeefForAtomic leaves
// an older unrelated one, which go-sdk's own Atomic parser refuses, is
// admitted; neither the BEEF stored nor the one a lookup answers with holds
// the unrelated transaction.
func TestSubmit_StoresOnlyTheSubjectsGraph(t *testing.T) {
	eng, _, url := normEngine(t)
	const hash = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	subject := overlaytest.SpendingTx(t, uhrpOutput(t, hash))
	funding := subject.Inputs[0].SourceTransaction
	unrelated := beefnormtest.Parent(50, 1, 1000)
	body := beefnormtest.Atomic(subject, beefnormtest.Encode(t, transaction.BEEF_V2, subject, []*transaction.MerklePath{funding.MerklePath}, unrelated, funding))
	if _, _, err := transaction.NewBeefFromAtomicBytes(body); err == nil {
		t.Fatal("go-sdk accepts the unrelated transaction; the case is not the one ts-sdk sends")
	}
	if code, resp := postSubmit(t, url, body); code != http.StatusOK {
		t.Fatalf("submit: %d %s", code, resp)
	}
	stored := storedBEEF(t, eng, subject.TxID())
	if stored.FindTransactionByHash(unrelated.TxID()) != nil || stored.FindTransactionByHash(funding.TxID()) == nil {
		t.Error("the stored BEEF holds the unrelated transaction or lacks the funding one")
	}
	code, answered := lookupUHRP(t, url, hash, false)
	if code != http.StatusOK || len(answered) != 1 || answered[0].FindTransactionByHash(unrelated.TxID()) != nil {
		t.Errorf("lookup: %d, %d outputs, or the answer holds the unrelated transaction", code, len(answered))
	}
}

// TestSubmit_ConsolidationOfAThousandParents: a transaction spending 1,000
// parents mined in one block of 2^20 transactions, proven by the one trimmed
// compound path an honest wallet sends, is admitted in V2, V1 and Atomic
// form, and stored with one canonical BUMP.
func TestSubmit_ConsolidationOfAThousandParents(t *testing.T) {
	eng, hs, url := normEngine(t)
	const k, levels = 1000, 20
	parents := make([]*transaction.Transaction, k)
	txids := make([]*chainhash.Hash, k)
	offsets := make([]uint64, k)
	idx := make([]int, k)
	for i := range parents {
		parents[i] = beefnormtest.Parent(uint64(1<<40|i), 1, 1000)                   //nolint:gosec // i >= 0
		txids[i], offsets[i], idx[i] = parents[i].TxID(), uint64(i)*(1<<levels/k), i //nolint:gosec // i >= 0
	}
	blk := beefnormtest.NewBlock(overlaytest.FundingHeight+1, levels, txids, offsets)
	addBlock(t, hs, blk.Root())
	path := blk.Compound(idx...)
	subject := transaction.NewTransaction()
	for _, p := range parents {
		p.MerklePath = path
		subject.AddInputFromTx(p, 0, nil)
		subject.Inputs[len(subject.Inputs)-1].UnlockingScript = &script.Script{}
	}
	subject.AddOutput(uhrpOutput(t, "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"))
	bumps := []*transaction.MerklePath{path}
	v2 := beefnormtest.Encode(t, transaction.BEEF_V2, subject, bumps, parents...)
	for _, c := range []struct {
		name string
		body []byte
	}{
		{"V2", v2},
		{"V1", beefnormtest.Encode(t, transaction.BEEF_V1, subject, bumps, parents...)},
		{"Atomic", beefnormtest.Atomic(subject, v2)},
	} {
		start := time.Now()
		if code, resp := postSubmit(t, url, c.body); code != http.StatusOK {
			t.Fatalf("%s: %d %s", c.name, code, resp)
		}
		t.Logf("%s: %d bytes admitted in %v", c.name, len(c.body), time.Since(start))
	}
	stored := storedBEEF(t, eng, subject.TxID())
	if len(stored.BUMPs) != 1 || len(stored.Transactions) != k+1 {
		t.Errorf("stored: %d BUMPs and %d transactions, want 1 and %d", len(stored.BUMPs), len(stored.Transactions), k+1)
	}
}

// TestSubmit_StoresAShortProofAtFullHeight: two submits prove one parent with
// paths of different heights, a single-level path of the block's four leaves
// and the usual two-level one. Each is stored as the two-level canonical
// path, so a lookup that merges both stored BEEFs combines paths of one
// height and answers.
func TestSubmit_StoresAShortProofAtFullHeight(t *testing.T) {
	eng, hs, url := normEngine(t)
	tru := beefnormtest.Lock()
	a := overlaytest.SpendingTx(t, &transaction.TransactionOutput{LockingScript: tru, Satoshis: 40_000}, &transaction.TransactionOutput{LockingScript: tru, Satoshis: 40_000})
	f := []*chainhash.Hash{a.TxID()}
	for i := 1; i < 4; i++ {
		h := chainhash.DoubleHashH([]byte{byte(i), 0xcc})
		f = append(f, &h)
	}
	l01, l11 := transaction.MerkleTreeParent(f[0], f[1]), transaction.MerkleTreeParent(f[2], f[3])
	height := addBlock(t, hs, transaction.MerkleTreeParent(l01, l11))
	yes := true
	tall := transaction.NewMerklePath(height, [][]*transaction.PathElement{
		{{Offset: 0, Hash: f[0], Txid: &yes}, {Offset: 1, Hash: f[1]}},
		{{Offset: 1, Hash: l11}},
	})
	short := transaction.NewMerklePath(height, [][]*transaction.PathElement{
		{{Offset: 0, Hash: f[0], Txid: &yes}, {Offset: 1, Hash: f[1]}, {Offset: 2, Hash: f[2]}, {Offset: 3, Hash: f[3]}},
	})
	const hash = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	for vout, mp := range []*transaction.MerklePath{tall, short} {
		parent := transaction.NewTransaction()
		parent.Version, parent.Inputs, parent.Outputs, parent.LockTime = a.Version, a.Inputs, a.Outputs, a.LockTime
		parent.MerklePath = mp
		x := transaction.NewTransaction()
		x.AddInputFromTx(parent, uint32(vout), nil) //nolint:gosec // 0 or 1
		x.Inputs[0].UnlockingScript = &script.Script{}
		x.AddOutput(uhrpOutput(t, hash))
		body, err := x.AtomicBEEF(false)
		if err != nil {
			t.Fatal(err)
		}
		if code, resp := postSubmit(t, url, body); code != http.StatusOK {
			t.Fatalf("submit %d: %d %s", vout, code, resp)
		}
		for _, bump := range storedBEEF(t, eng, x.TxID()).BUMPs {
			if bump.BlockHeight == height && len(bump.Path) != 2 {
				t.Errorf("submit %d: stored a path of %d levels for block %d", vout, len(bump.Path), height)
			}
		}
	}
	code, answered := lookupUHRP(t, url, hash, false)
	if code != http.StatusOK || len(answered) != 2 {
		t.Fatalf("lookup: %d, %d outputs", code, len(answered))
	}
	if code, _ := lookupUHRP(t, url, hash, true); code != http.StatusOK {
		t.Errorf("aggregated lookup: %d", code)
	}
}

// TestSubmit_RefusesSpendsOnlyTheExtendedFormatBacks: a transaction whose
// spent output only the extended format supplies, with 15 million
// instructions there (2.1 GB to verify unpriced) or an OP_CAT doubling a push
// to 32 MiB (outside the execution slot), is refused with 400 before any
// script is priced or run, within the heap its body reserves; so are
// routeguard.CPUSlots of the latter at once.
func TestSubmit_RefusesSpendsOnlyTheExtendedFormatBacks(t *testing.T) {
	_, _, url := normEngine(t)
	push := bytes.Repeat([]byte{0x42}, 1000)
	cat := append([]byte{script.OpPUSHDATA2, byte(len(push)), byte(len(push) >> 8)}, push...)
	for i := 0; i < 15; i++ {
		cat = append(cat, script.OpDUP, script.OpCAT)
	}
	cat = append(cat, script.OpDROP, script.OpTRUE)
	long := append(bytes.Repeat([]byte{script.OpNOP}, 15_000_000), script.OpTRUE)
	for name, lock := range map[string][]byte{"15 million instructions": long, "OP_CAT to 32 MiB": cat} {
		body := efSpendBEEF(t, lock)
		var code int
		var resp []byte
		start := time.Now()
		peak, _ := hostiletest.HeapPeak(func() { code, resp = postSubmit(t, url, body) })
		took := time.Since(start)
		reserved, _ := routeguard.BEEFRoute.Reservation(int64(len(body)))
		t.Logf("%s: %d bytes -> %d in %v, heap peak %.1f MiB of %.1f MiB reserved", name, len(body), code, took, float64(peak)/(1<<20), float64(reserved)/(1<<20))
		if code != http.StatusBadRequest || !strings.Contains(string(resp), "extended format") {
			t.Errorf("%s: %d %s, want 400", name, code, resp)
		}
		if peak > uint64(reserved) { //nolint:gosec // reserved > 0
			t.Errorf("%s: heap peak %d over the %d reserved", name, peak, reserved)
		}
	}
	body := efSpendBEEF(t, cat)
	codes := make([]int, routeguard.CPUSlots)
	peak, _ := hostiletest.HeapPeak(func() {
		var wg sync.WaitGroup
		for i := range codes {
			wg.Add(1)
			go func(i int) { defer wg.Done(); codes[i], _ = postSubmit(t, url, body) }(i)
		}
		wg.Wait()
	})
	t.Logf("%d at once: %v, heap peak %.1f MiB", len(codes), codes, float64(peak)/(1<<20))
	for i, code := range codes {
		if code != http.StatusBadRequest {
			t.Errorf("concurrent submit %d: %d, want 400", i, code)
		}
	}
	if peak > uint64(routeguard.ExecAllowance) {
		t.Errorf("heap peak %d over the execution slot's %d", peak, routeguard.ExecAllowance)
	}
}
