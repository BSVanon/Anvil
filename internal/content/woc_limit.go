package content

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// maxWoCTxHexBytes caps how much of a WhatsOnChain transaction reply
// fetchRawTxFromWoC reads, on both the /hex path and the JSON fallback: 32 MiB
// of hex is a 16 MiB transaction. WoC already returns nothing for the large
// ordinal transactions that come near that size, so the cap is defense in
// depth. It stops a misbehaving or spoofed upstream from streaming an
// unbounded body into memory through the public GET /content/{origin} route.
// The JSON fallback carries the hex plus other fields, so holding its body to
// the same budget also bounds the hex inside it.
const maxWoCTxHexBytes = 32 << 20

// maxWoCMetadataBytes caps WoC replies that carry only small JSON metadata —
// a tx-status lookup, a TSC merkle-proof target, or a basic tx-info object —
// used solely to locate the block containing a transaction (findBlockHash's
// three helpers). These never become served content, so a far smaller cap
// than maxWoCTxHexBytes is plenty, and it bounds memory the same way against
// a misbehaving or oversized upstream reply.
const maxWoCMetadataBytes = 1 << 20

// errWoCResponseTooLarge is returned when a WoC reply exceeds its cap.
var errWoCResponseTooLarge = errors.New("WoC response exceeds size cap")

// readWoCBodyLimited reads body, failing once it passes max bytes.
func readWoCBodyLimited(body io.Reader, max int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(body, max+1))
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%w: more than %d bytes", errWoCResponseTooLarge, max)
	}
	return b, nil
}

// readWoCBody reads body, failing once it passes maxWoCTxHexBytes.
func readWoCBody(body io.Reader) ([]byte, error) {
	return readWoCBodyLimited(body, maxWoCTxHexBytes)
}

// decodeWoCJSON reads body through readWoCBody's cap and decodes it into v.
func decodeWoCJSON(body io.Reader, v any) error {
	b, err := readWoCBody(body)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// decodeWoCMetadata reads body through maxWoCMetadataBytes and decodes it
// into v. Used by the block-locating helpers (tryWoCStatus, tryWoCProof,
// tryWoCConfirmation), which only ever need a small JSON payload and never
// return bytes served as a transaction's content.
func decodeWoCMetadata(body io.Reader, v any) error {
	b, err := readWoCBodyLimited(body, maxWoCMetadataBytes)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
