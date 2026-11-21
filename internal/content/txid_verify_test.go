package content

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

// TestLogTxidMismatchDistinguishesDecodeFailureFromHashMismatch requires the
// log line to say which of the two failure modes verifyTxidMatch
// hit — a malformed (non-hex) body versus bytes that decode fine but hash to
// the wrong txid — rather than one generic message for both.
func TestLogTxidMismatchDistinguishesDecodeFailureFromHashMismatch(t *testing.T) {
	var logged bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logged, nil))
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })
	slog.SetDefault(logger)

	srv := NewServer("", nil, nil, nil)

	hashErr := verifyTxidMatch("aabbcc", strings.Repeat("0", 64)) // valid hex, wrong hash
	if !errors.Is(hashErr, errTxidMismatch) {
		t.Fatalf("expected errTxidMismatch, got %v", hashErr)
	}
	srv.txidMismatchLimiter.logTxidMismatch("source_a", "txid_a", hashErr)
	if !strings.Contains(logged.String(), "did not hash to requested txid") {
		t.Fatalf("expected a hash-mismatch message, got:\n%s", logged.String())
	}
	logged.Reset()

	decodeErr := verifyTxidMatch("not-hex!!", strings.Repeat("0", 64))
	if errors.Is(decodeErr, errTxidMismatch) {
		t.Fatalf("a hex-decode failure must not satisfy errors.Is(_, errTxidMismatch), got %v", decodeErr)
	}
	srv.txidMismatchLimiter.logTxidMismatch("source_b", "txid_b", decodeErr)
	if !strings.Contains(logged.String(), "failed to decode") {
		t.Fatalf("expected a decode-failure message, got:\n%s", logged.String())
	}
	if strings.Contains(logged.String(), "did not hash to requested txid") {
		t.Fatalf("a decode failure must not be logged as a hash mismatch:\n%s", logged.String())
	}
}

// TestTxidMismatchLimiterRateLimitsPerSource is the existing rate-limit
// behavior (one warning per source per txidMismatchLogInterval), now
// exercised against the *Server field rather than the old package global.
func TestTxidMismatchLimiterRateLimitsPerSource(t *testing.T) {
	var logged bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logged, nil))
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })
	slog.SetDefault(logger)

	srv := NewServer("", nil, nil, nil)

	srv.txidMismatchLimiter.logTxidMismatch("dup_source", "txid", errTxidMismatch)
	firstLen := logged.Len()
	if firstLen == 0 {
		t.Fatal("expected the first warning to be logged")
	}
	srv.txidMismatchLimiter.logTxidMismatch("dup_source", "txid", errTxidMismatch)
	if logged.Len() != firstLen {
		t.Fatal("a second warning for the same source within the interval must be suppressed")
	}
	srv.txidMismatchLimiter.logTxidMismatch("other_source", "txid", errTxidMismatch)
	if logged.Len() == firstLen {
		t.Fatal("a different source must not be suppressed by another source's rate limit")
	}
}

// TestTxidMismatchLimiterNotSharedAcrossServers verifies that the limiter used
// to be a package-level var (the old txidMismatchLog), so one *Server's
// warning could silently suppress another's — a hazard for two servers in
// one process, and for any test that assumed a clean rate-limit state. It
// is now serve.go's Server.txidMismatchLimiter field, constructed fresh per
// NewServer call; this proves a new *Server is never pre-suppressed by
// another *Server's history.
func TestTxidMismatchLimiterNotSharedAcrossServers(t *testing.T) {
	var logged bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logged, nil))
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })
	slog.SetDefault(logger)

	srvA := NewServer("", nil, nil, nil)
	srvB := NewServer("", nil, nil, nil)

	srvA.txidMismatchLimiter.logTxidMismatch("same_source", "txid", errTxidMismatch)
	firstLen := logged.Len()
	if firstLen == 0 {
		t.Fatal("expected srvA's warning to be logged")
	}

	// If this were still a package global, srvB would inherit srvA's
	// just-set timestamp for "same_source" and this call would be
	// suppressed.
	srvB.txidMismatchLimiter.logTxidMismatch("same_source", "txid", errTxidMismatch)
	if logged.Len() == firstLen {
		t.Fatal("srvB's rate limiter must not be suppressed by srvA's state")
	}
}
