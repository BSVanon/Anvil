package v3engine

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/overlay/overlaytest"
	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
	"github.com/bsv-blockchain/go-sdk/util"
)

// The v3.5.0 security regressions for POST /submit, which reaches go-sdk's
// BEEF parser and spv.Verify with no login. go-sdk v1.2.23 could be crashed
// there by a wire-sized allocation or by unbounded script stack memory, and
// CPU-exhausted by diamond-shaped ancestry or a crafted BUMP. go-sdk v1.7.7
// closes each one, and these tests pin that.

// cpuBound is how long a hostile BEEF may keep engine.Submit busy in these
// tests. On v1.7.7 each case takes about a millisecond. On v1.2.23 the same
// inputs ran for hours or more (the cost doubled with every diamond tx or
// BUMP level), so a regression fails loudly instead of only getting slower.
const cpuBound = 2 * time.Second

// postSubmit POSTs body to /submit for tm_uhrp and returns the status code and
// response body.
func postSubmit(t *testing.T, url string, body []byte) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url+"/submit", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("x-topics", `["`+topics.UHRPTopicName+`"]`)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /submit: %v", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /submit response: %v", err)
	}
	return resp.StatusCode, raw
}

// submitWithin runs eng.Submit on beef in a goroutine and fails the test if it
// has not returned within cpuBound. A hung Submit is left running so the test
// can report it instead of hanging the suite.
func submitWithin(t *testing.T, eng *engine.Engine, beef []byte) error {
	t.Helper()
	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := eng.Submit(context.Background(), overlay.TaggedBEEF{
			Beef:   beef,
			Topics: []string{topics.UHRPTopicName},
		}, engine.SubmitModeCurrent, nil)
		done <- err
	}()
	select {
	case err := <-done:
		t.Logf("engine.Submit returned in %v (bound %v)", time.Since(start), cpuBound)
		return err
	case <-time.After(cpuBound):
		t.Fatalf("engine.Submit still running after %v: CPU-exhaustion regression", cpuBound)
		return nil
	}
}

// TestSubmitHandler_OversizedBEEFCountRejected: this 16-byte body (BEEF V1,
// 1 BUMP, block height 0, tree height 1, nLeaves = 2^36) made go-sdk v1.2.23
// size a merkle-path leaf slice from the wire and die of a fatal
// out-of-memory error. It must now be an ordinary 400 naming the guard.
func TestSubmitHandler_OversizedBEEFCountRejected(t *testing.T) {
	url := newTestServer(t)
	body := []byte{0x01, 0x00, 0xBE, 0xEF, 0x01, 0x00, 0x01, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00}
	status, raw := postSubmit(t, url, body)
	if status != http.StatusBadRequest {
		t.Fatalf("expected 400 for an oversized merkle-path leaf count, got %d: %s", status, raw)
	}
	assertCanonicalErrorEnvelope(t, bytes.NewReader(raw), "merkle path leaves count 68719476736 exceeds capacity")
}

// TestSubmitHandler_StackMemoryBombRejected: an unmined output whose locking
// script doubles one stack element 28 times (OP_DUP OP_CAT, to 256 MiB) and
// then keeps 24 more 256 MiB copies. In a ~218-byte V1 BEEF, this script was
// reported to drive go-sdk v1.2.23's interpreter, which had no stack-memory
// cap, to a fatal out-of-memory error inside spv.Verify. v1.7.7 caps script
// stack memory at bitcoin-sv's 100,000,000-byte relay policy
// (interpreter.DefaultMaxStackMemory, GHSA-rh54-8fpg-8wwf), so the spend must
// fail script verification with a 400 once the element reaches 64 MiB. The
// chain is otherwise valid: the bomb's own transaction spends overlaytest's
// funding output.
func TestSubmitHandler_StackMemoryBombRejected(t *testing.T) {
	lock := []byte{script.Op1}
	for i := 0; i < 28; i++ {
		lock = append(lock, script.OpDUP, script.OpCAT)
	}
	for i := 0; i < 24; i++ {
		lock = append(lock, script.OpDUP, script.Op1, script.OpCAT)
	}
	bomb := script.Script(lock)
	bombTx := overlaytest.SpendingTx(t, &transaction.TransactionOutput{LockingScript: &bomb, Satoshis: 1})

	spend := transaction.NewTransaction()
	spend.AddInputFromTx(bombTx, 0, nil)
	spend.Inputs[0].UnlockingScript = &script.Script{}
	opReturn := script.Script{script.OpFALSE, script.OpRETURN}
	spend.AddOutput(&transaction.TransactionOutput{LockingScript: &opReturn, Satoshis: 0})
	beef, err := spend.BEEF()
	if err != nil {
		t.Fatalf("BEEF: %v", err)
	}

	url := newTestServer(t)
	status, raw := postSubmit(t, url, beef)
	if status != http.StatusBadRequest {
		t.Fatalf("expected 400 for a stack-memory bomb, got %d: %s", status, raw)
	}
	assertCanonicalErrorEnvelope(t, bytes.NewReader(raw), "over the limit of 100000000")
}

// diamondChainBEEFV1 returns a V1 BEEF of overlaytest's funding tx (with its
// BUMP) and n+1 unmined transactions above it. The first spends the funding
// output into two OP_TRUE outputs; each later one spends both outputs of the
// one before into two more. Every transaction is therefore reachable from the
// tip along 2^depth paths. The bytes are written by hand, so building the
// fixture never walks the ancestry.
func diamondChainBEEFV1(t *testing.T, n int) []byte {
	t.Helper()
	lock := script.Script{script.OpTRUE}
	pair := func() []*transaction.TransactionOutput {
		return []*transaction.TransactionOutput{{LockingScript: &lock, Satoshis: 1}, {LockingScript: &lock, Satoshis: 1}}
	}
	first := overlaytest.SpendingTx(t, pair()...)
	funding := first.Inputs[0].SourceTransaction

	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, transaction.BEEF_V1)
	buf.Write(util.VarInt(1).Bytes()) // one BUMP: the funding tx's
	buf.Write(funding.MerklePath.Bytes())
	buf.Write(util.VarInt(n + 2).Bytes())
	buf.Write(funding.Bytes())
	buf.Write([]byte{0x01, 0x00}) // has a BUMP, index 0
	buf.Write(first.Bytes())
	buf.WriteByte(0x00)
	prev := first
	for i := 0; i < n; i++ {
		tx := transaction.NewTransaction()
		for vout := uint32(0); vout < 2; vout++ {
			tx.AddInputFromTx(prev, vout, nil)
			tx.Inputs[vout].UnlockingScript = &script.Script{}
		}
		for _, out := range pair() {
			tx.AddOutput(out)
		}
		buf.Write(tx.Bytes())
		buf.WriteByte(0x00)
		prev = tx
	}
	return buf.Bytes()
}

// TestEngine_DiamondChainBEEFVerifiesWithinBound: go-sdk v1.2.23 walked
// ancestry (BEEF parsing, then spv.Verify's queue) once per path, so the cost
// doubled with every diamond transaction: a 2.3 KB BEEF took 3.9 s. v1.7.5+
// walks each transaction once. This 41-transaction diamond chain (about 4.6
// KB) is valid, so it must verify and be accepted, within cpuBound.
func TestEngine_DiamondChainBEEFVerifiesWithinBound(t *testing.T) {
	eng, _ := newTestEngine(t)
	if err := submitWithin(t, eng, diamondChainBEEFV1(t, 40)); err != nil {
		t.Fatalf("a valid diamond chain must be accepted, got: %v", err)
	}
}

// merkleBombBEEFV1 returns a V1 BEEF of one transaction whose BUMP claims a
// tree of height 64 at block 100. It gives the txid and a sibling at level 0
// and only an offset-1 node at each of levels 1..k-1, leaving every node the
// root needs to be computed. go-sdk v1.2.23's MerklePath.GetOffsetLeaf
// recomputed those without memoizing, at a cost doubling with every level.
func merkleBombBEEFV1(k int) []byte {
	lock := script.Script{script.OpTRUE}
	tx := transaction.NewTransaction()
	tx.AddOutput(&transaction.TransactionOutput{LockingScript: &lock, Satoshis: 1})
	isTxid := true
	sibling := chainhash.Hash{1}
	path := make([][]*transaction.PathElement, 64)
	path[0] = []*transaction.PathElement{{Offset: 0, Hash: tx.TxID(), Txid: &isTxid}, {Offset: 1, Hash: &sibling}}
	for l := 1; l < 64; l++ {
		path[l] = []*transaction.PathElement{}
		if l < k {
			path[l] = append(path[l], &transaction.PathElement{Offset: 1, Hash: &sibling})
		}
	}
	mp := transaction.NewMerklePath(100, path)

	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, transaction.BEEF_V1)
	buf.Write(util.VarInt(1).Bytes())
	buf.Write(mp.Bytes())
	buf.Write(util.VarInt(1).Bytes())
	buf.Write(tx.Bytes())
	buf.Write([]byte{0x01, 0x00}) // has a BUMP, index 0
	return buf.Bytes()
}

// TestEngine_MerkleBombBEEFRejectedWithinBound: on go-sdk v1.2.23 this BUMP
// cost about 1.7 ms at 18 levels and doubled per level, so 63 levels would run
// for centuries. v1.7.5+ computes the path in linear time. The BUMP lacks the
// nodes its root needs, so computing the root must fail, within cpuBound.
func TestEngine_MerkleBombBEEFRejectedWithinBound(t *testing.T) {
	eng, _ := newTestEngine(t)
	err := submitWithin(t, eng, merkleBombBEEFV1(63))
	if err == nil {
		t.Fatal("a BUMP that proves nothing must be rejected")
	}
	if !strings.Contains(err.Error(), "we do not have a hash for this index") {
		t.Fatalf("expected the merkle root computation to fail, got: %v", err)
	}
}
