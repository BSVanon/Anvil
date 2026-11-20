package gateway

import "fmt"

// testTxid returns a deterministic, valid 64-hex-char txid for tests,
// varied by n. Zero-padded hex formatting guarantees the exact length by
// construction, so tests never risk a hand-typed hex string of the wrong
// length.
func testTxid(n int) string {
	return fmt.Sprintf("%064x", n)
}

// testOutpoint returns a valid "txid_vout" string for test n at the given
// vout.
func testOutpoint(n, vout int) string {
	return fmt.Sprintf("%s_%d", testTxid(n), vout)
}
