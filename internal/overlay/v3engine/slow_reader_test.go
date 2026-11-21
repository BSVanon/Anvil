package v3engine

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/overlay/overlaytest"
	"github.com/BSVanon/Anvil/internal/overlay/routeguard"
	"github.com/BSVanon/Anvil/internal/overlay/topics"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/engine"
	"github.com/bsv-blockchain/go-sdk/overlay"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// bigUHRPAnswer submits n UHRP advertisements for one content hash in a
// single transaction, and returns that hash: a /lookup for it then answers
// with n hydrated outputs. Each hydrated OutputListItem embeds the whole
// submitting transaction, so the marshalled answer's size grows with
// roughly the square of n — measured, n=200 answers about 15 MiB — which
// matters here because writing a small answer to a connection that never
// reads it never blocks (measured on this system: 4 MiB never does within
// 1.5s, 8 MiB always does), so a test of what happens while that write is
// stuck needs an answer in that range, not a token-sized one.
func bigUHRPAnswer(t *testing.T, eng *engine.Engine, n int) string {
	t.Helper()
	hashBytes := make([]byte, 32)
	for i := range hashBytes {
		hashBytes[i] = 0xcc
	}
	hashHex := fmt.Sprintf("%x", hashBytes)
	outs := make([]*transaction.TransactionOutput, 0, n)
	for i := 0; i < n; i++ {
		url := "https://example.test/" + strings.Repeat("x", 230) + strconv.Itoa(i)
		scriptBytes := []byte{0x00, 0x6a, byte(len(topics.UHRPProtocolID))}
		scriptBytes = append(scriptBytes, []byte(topics.UHRPProtocolID)...)
		scriptBytes = append(scriptBytes, byte(len(hashBytes)))
		scriptBytes = append(scriptBytes, hashBytes...)
		scriptBytes = append(scriptBytes, byte(len(url)))
		scriptBytes = append(scriptBytes, []byte(url)...)
		s := script.Script(scriptBytes)
		outs = append(outs, &transaction.TransactionOutput{LockingScript: &s, Satoshis: 0})
	}
	tx := overlaytest.SpendingTx(t, outs...)
	tagged := overlay.TaggedBEEF{Beef: encodeFixtureBEEF(t, tx, true), Topics: []string{topics.UHRPTopicName}}
	steak, err := eng.Submit(context.Background(), tagged, engine.SubmitModeHistorical, nil)
	if err != nil {
		t.Fatalf("submit %d UHRP outputs: %v", n, err)
	}
	if inst := steak[topics.UHRPTopicName]; inst == nil || len(inst.OutputsToAdmit) != n {
		t.Fatalf("admitted %v of %d outputs", inst, n)
	}
	return hashHex
}

// neverReadingLookup opens a raw connection, sends a complete, honestly
// declared /lookup POST for hashHex, and returns once the request is fully
// on the wire — without reading one byte of the answer, simulating a
// client that opens the connection and then never reads it at all.
func neverReadingLookup(t *testing.T, url, hashHex string) net.Conn {
	t.Helper()
	q, err := json.Marshal(map[string]any{"service": topics.UHRPLookupServiceName, "query": topics.UHRPLookupQuery{ContentHash: hashHex}})
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", strings.TrimPrefix(url, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	req := "POST /lookup HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(q)) + "\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(q); err != nil {
		t.Fatal(err)
	}
	return conn
}

// TestGuard_SlowAnswerReadersDoNotStarveJSONSlots reproduces the B4a
// review's scaled-pool probe: on a guard scaled down to 3 JSON slots, 3
// clients that send a complete lookup request and then never read their
// (large) answer must not starve a 4th, honest client. Before the fix each
// of the 3 held its JSON slot until its answer was fully written — which,
// writing to a connection that never reads, does not happen — so the slot
// was held for as long as the connection stayed open, not for as long as
// producing the answer actually took.
func TestGuard_SlowAnswerReadersDoNotStarveJSONSlots(t *testing.T) {
	eng, _ := newTestEngine(t)
	const scaledJSONSlots = 3
	g := routeguard.New(routeguard.MemoryBudget-routeguard.ExecAllowance, routeguard.CPUSlots, scaledJSONSlots, routeguard.Wait)
	url := guardedServer(t, eng, g)

	hashHex := bigUHRPAnswer(t, eng, 200)
	if code, _, took := honestLookup(t, url); code != http.StatusOK {
		t.Fatalf("honest lookup before any slow reader: %d in %v", code, took)
	}

	slow := make([]net.Conn, scaledJSONSlots)
	for i := range slow {
		slow[i] = neverReadingLookup(t, url, hashHex)
	}
	// Give each slow reader's request time to be read, its answer looked
	// up, marshalled, and (with the fix) its ticket released — all well
	// under a second for a 200-output answer — before the honest probe.
	time.Sleep(1 * time.Second)

	const probeBound = 5 * time.Second
	code, _, took := honestLookup(t, url)
	t.Logf("honest lookup with %d slow readers open: %d in %v", len(slow), code, took)
	if code != http.StatusOK || took > probeBound {
		t.Fatalf("honest lookup with every JSON slot opened by a slow reader: %d in %v, want 200 within %v "+
			"(a slot held until its answer is written, not released once the answer is ready, starves every other JSON route)",
			code, took, probeBound)
	}
}
