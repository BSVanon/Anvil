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

// errWoCResponseTooLarge is returned when a WoC reply exceeds maxWoCTxHexBytes.
var errWoCResponseTooLarge = errors.New("WoC response exceeds size cap")

// readWoCBody reads body, failing once it passes maxWoCTxHexBytes.
func readWoCBody(body io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(body, maxWoCTxHexBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	if len(b) > maxWoCTxHexBytes {
		return nil, fmt.Errorf("%w: more than %d bytes", errWoCResponseTooLarge, maxWoCTxHexBytes)
	}
	return b, nil
}

// decodeWoCJSON reads body through readWoCBody's cap and decodes it into v.
func decodeWoCJSON(body io.Reader, v any) error {
	b, err := readWoCBody(body)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
