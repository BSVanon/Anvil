package content

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/bsv-blockchain/go-sdk/chainhash"
)

// errTxidMismatch is wrapped by verifyTxidMatch's error so callers can
// distinguish a hash mismatch from a hex-decode failure.
var errTxidMismatch = errors.New("fetched bytes do not hash to the requested txid")

// verifyTxidMatch decodes rawHex and reports an error unless its
// double-SHA256, byte-reversed hash equals txid. chainhash.DoubleHashH is
// go-sdk's own primitive — the same computation transaction.Transaction.TxID
// performs on parsed bytes — so this is the SDK's hash, not a reimplementation.
//
// fetchRawTx wraps every source (block cache, P2P single-tx fetch,
// WhatsOnChain hex and JSON, P2P block fetch) with this call before letting
// its bytes become the result: a source that returns someone else's
// transaction — a bug, a cache-key confusion upstream, or a hostile reply —
// fails exactly like a network error, so fetchRawTx moves on to its next
// source instead of serving or caching the wrong content under this txid.
func verifyTxidMatch(rawHex string, txid string) error {
	raw, err := hex.DecodeString(strings.TrimSpace(rawHex))
	if err != nil {
		return fmt.Errorf("decode hex: %w", err)
	}
	got := chainhash.DoubleHashH(raw).String()
	if !strings.EqualFold(got, txid) {
		return fmt.Errorf("%w: got %s want %s", errTxidMismatch, got, txid)
	}
	return nil
}

// txidMismatchLogInterval rate-limits mismatch warnings to at most one line
// per source per interval: a source that is persistently wrong — or under
// attack — must not be able to flood the log the way its mismatched bytes
// are kept from flooding the cache or a client response.
const txidMismatchLogInterval = time.Minute

var txidMismatchLog = struct {
	mu   sync.Mutex
	last map[string]time.Time
}{last: make(map[string]time.Time)}

// logTxidMismatch warns that source returned bytes which did not hash to
// txid, at most once per source per txidMismatchLogInterval.
func logTxidMismatch(source, txid string) {
	now := time.Now()
	txidMismatchLog.mu.Lock()
	last, ok := txidMismatchLog.last[source]
	logNow := !ok || now.Sub(last) >= txidMismatchLogInterval
	if logNow {
		txidMismatchLog.last[source] = now
	}
	txidMismatchLog.mu.Unlock()

	if logNow {
		slog.Warn("content: fetched tx bytes did not match requested txid", "source", source, "txid", txid)
	}
}
