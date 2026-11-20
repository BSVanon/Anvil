package netguard

import (
	"bytes"
	"log/slog"
	"math/rand"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/transaction"
)

// TestGaspNodeMalformed_RecoversAPanic: cold review round 4 cycle 6's RISK 3
// -- gaspNodeMalformed parsed untrusted hex with no recover of its own --
// fixed by running the parse under netguard.Contain. With
// parseGASPTransaction swapped for a stub that panics, the call is refused
// (a non-empty reason, fail closed) instead of ending the process, and
// Contain's own logging names the site and the panic value for attribution.
func TestGaspNodeMalformed_RecoversAPanic(t *testing.T) {
	prior := parseGASPTransaction
	t.Cleanup(func() { parseGASPTransaction = prior })
	parseGASPTransaction = func([]byte) (*transaction.Transaction, error) { panic("gasp parse bug") }

	var logged bytes.Buffer
	prevLogger := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prevLogger) })
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, nil)))

	node, _, err := decodeGASPNode(gaspNodeReply(t, honestTx(t)))
	if err != nil {
		t.Fatalf("decodeGASPNode: %v", err)
	}
	reason := gaspNodeMalformed(node)
	if reason == "" {
		t.Fatal("want a refusal reason when the transaction parse panics, got none (fail open on panic)")
	}
	if !strings.Contains(reason, "gasp parse bug") {
		t.Errorf("reason %q does not name the panic", reason)
	}
	if !strings.Contains(logged.String(), "netguard.gaspNodeMalformed") || !strings.Contains(logged.String(), "gasp parse bug") {
		t.Errorf("the panic was not logged with its site for attribution:\n%s", logged.String())
	}
}

// gaspNodeMutationRounds is how many mutated inputs
// TestGaspNodeMalformed_MutatedTransactionsNeverPanic runs through the real
// parser. Cold review round 4 cycle 6's original probe ran 400,000 and found
// no panic; this permanent regression keeps the same mutation shapes at a
// tenth of that, fast enough for every run (including -race), since the
// recover itself is already proven deterministically by
// TestGaspNodeMalformed_RecoversAPanic above -- this test's job is breadth
// against the real parser, not reproving the recover fires.
const gaspNodeMutationRounds = 40_000

// TestGaspNodeMalformed_MutatedTransactionsNeverPanic is cold review round
// 4 cycle 6's parse-panic probe, adapted into a permanent regression:
// mutations of a malformed and an honest transaction's raw bytes, decoded
// into a gasp.Node and run through the real, unswapped parseGASPTransaction
// (transaction.NewTransactionFromBytes), must never panic past
// gaspNodeMalformed and into this goroutine. Whether that holds because the
// parser itself never panics on these mutations, or because Contain
// recovers one that does, is not this test's concern -- it only needs the
// process to survive either way.
func TestGaspNodeMalformed_MutatedTransactionsNeverPanic(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	base := malformedReparseTx(t)
	honest := honestTx(t)
	seeds := [][]byte{base, honest}
	n := 0
	defer func() {
		if p := recover(); p != nil {
			t.Fatalf("panic after %d inputs: %v", n, p)
		}
	}()
	for i := 0; i < gaspNodeMutationRounds; i++ {
		s := append([]byte{}, seeds[r.Intn(2)]...)
		switch r.Intn(4) {
		case 0:
			s = s[:r.Intn(len(s)+1)]
		case 1:
			for j := 0; j < 1+r.Intn(4); j++ {
				s[r.Intn(len(s))] = byte(r.Intn(256))
			}
		case 2:
			for j := 0; j < 1+r.Intn(3); j++ {
				p := r.Intn(len(s))
				s = append(s[:p], append([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}[:r.Intn(9)+1], s[p:]...)...)
			}
		default:
			s = make([]byte, r.Intn(64))
			_, _ = r.Read(s)
		}
		n++
		node, _, err := decodeGASPNode(gaspNodeReply(t, s))
		if err != nil {
			continue // gaspNodeReply's JSON/hex framing is always well-formed; not this probe's concern
		}
		_ = gaspNodeMalformed(node)
	}
	t.Logf("%d mutated rawTx replies through gaspNodeMalformed: no panic", n)
}
