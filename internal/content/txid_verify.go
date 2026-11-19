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

// txidMismatchLimiter holds the per-source rate-limit state. It is a
// *Server field (see serve.go's Server.txidMismatchLimiter), not a package
// global: a package global would let state leak between independent
// *Server instances in different tests (or, in principle, different nodes
// in the same process), so one test's warning could silently suppress
// another's.
type txidMismatchLimiter struct {
	mu   sync.Mutex
	last map[string]time.Time
}

func newTxidMismatchLimiter() *txidMismatchLimiter {
	return &txidMismatchLimiter{last: make(map[string]time.Time)}
}

// logTxidMismatch warns that source returned bytes which failed
// verifyTxidMatch, at most once per source per txidMismatchLogInterval. err
// is verifyTxidMatch's own return value, so the log line can distinguish a
// hex-decode failure (malformed bytes) from a genuine hash mismatch
// (wrapping errTxidMismatch) — two different failure modes that a single
// generic message previously conflated.
func (l *txidMismatchLimiter) logTxidMismatch(source, txid string, err error) {
	now := time.Now()
	l.mu.Lock()
	last, ok := l.last[source]
	logNow := !ok || now.Sub(last) >= txidMismatchLogInterval
	if logNow {
		l.last[source] = now
	}
	l.mu.Unlock()

	if !logNow {
		return
	}
	if errors.Is(err, errTxidMismatch) {
		slog.Warn("content: fetched tx bytes did not hash to requested txid", "source", source, "txid", txid, "err", err)
		return
	}
	slog.Warn("content: fetched tx bytes failed to decode", "source", source, "txid", txid, "err", err)
}
