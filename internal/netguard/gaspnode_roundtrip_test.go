package netguard

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-overlay-services/pkg/core/gasp"
)

// gaspDownstreamDecode is exactly OverlayGASPRemote.doNodeRequest's own
// decode of a /requestForeignGASPNode reply (go-overlay-services
// pkg/core/engine/gasp-remote.go:184): one json.Decoder.Decode of the first
// JSON value. decodeGASPNode (gaspnode.go) is written to match this call
// exactly; gaspDownstreamDecode is a second, independent copy of it here, so
// a test using it can tell the two apart if they ever drift.
func gaspDownstreamDecode(body []byte) (*gasp.Node, error) {
	node := &gasp.Node{}
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(node); err != nil {
		return nil, err
	}
	return node, nil
}

// TestGuard_DecodeMatchesDoNodeRequest verifies that:
// across a wide range of edge-case /requestForeignGASPNode reply bodies
// (null and missing fields, duplicate and case-variant keys, escapes,
// invalid UTF-8, unknown fields, trailing junk, a leading BOM, a top-level
// array, odd-cased hex), decodeGASPNode's accept-or-refuse decision and, when
// it accepts, the node it decodes must match doNodeRequest's own decode of
// the same original bytes exactly -- never refusing a body doNodeRequest
// would accept (fail open on the real risk), and never accepting one it
// would not with a different result (gaspNodeMalformed and the bytes
// checkGASPNode hands on would then be judging bytes doNodeRequest itself
// reads differently).
//
// The original probe compared decodeGASPNode's result to a json.Marshal
// re-encoding of it redecoded downstream, because at the time checkGASPNode
// handed a re-encoded node on. That
// comparison no longer matches what the guard does: checkGASPNode now hands
// on decodeGASPNode's consumed return, body sliced to exactly the bytes one
// Decode call read, so this instead confirms that slice, redecoded the same
// way doNodeRequest decodes, still yields the identical node -- the
// property that matters now, that slicing at dec.InputOffset() neither
// drops bytes the decode actually used nor keeps any it did not.
func TestGuard_DecodeMatchesDoNodeRequest(t *testing.T) {
	txHex := hex.EncodeToString(honestTx(t))
	op := gaspOutpoint.String()
	upper := strings.ToUpper(op[:64])
	bodies := map[string]string{
		"full":                   fmt.Sprintf(`{"graphID":%q,"rawTx":%q,"outputIndex":3,"proof":"abcd","txMetadata":"m1","outputMetadata":"m2","inputs":{"k":{"hash":"h"},"n":null}}`, op, txHex),
		"graphID null":           fmt.Sprintf(`{"graphID":null,"rawTx":%q,"outputIndex":0}`, txHex),
		"graphID upper, odd sep": fmt.Sprintf(`{"graphID":%q,"rawTx":%q}`, upper+"X"+op[65:], txHex),
		"graphID idx 0007":       fmt.Sprintf(`{"graphID":%q,"rawTx":%q}`, op[:65]+"0007", txHex),
		"graphID absent":         fmt.Sprintf(`{"rawTx":%q}`, txHex),
		"proof empty":            fmt.Sprintf(`{"rawTx":%q,"proof":""}`, txHex),
		"proof null":             fmt.Sprintf(`{"rawTx":%q,"proof":null}`, txHex),
		"inputs empty":           fmt.Sprintf(`{"rawTx":%q,"inputs":{}}`, txHex),
		"dup keys last wins":     fmt.Sprintf(`{"rawTx":"zz","rawTx":%q,"proof":"x","proof":""}`, txHex),
		"case-variant keys":      fmt.Sprintf(`{"RAWTX":%q,"Proof":"p","pRoOf":""}`, txHex),
		"escapes":                fmt.Sprintf(`{"rawTx":%q,"txMetadata":"< \ud800\u0000<>&"}`, txHex),
		"invalid utf8":           "{\"rawTx\":\"" + txHex + "\",\"txMetadata\":\"\x80\xff\"}",
		"unknown fields":         fmt.Sprintf(`{"rawTx":%q,"x":[1,{"y":2}],"z":"q"}`, txHex),
		"trailing junk":          fmt.Sprintf(`{"rawTx":%q}xyz`, txHex),
		"rawTx null":             `{"rawTx":null}`,
		"outputIndex 1.0":        fmt.Sprintf(`{"rawTx":%q,"outputIndex":1.0}`, txHex),
		"graphID number":         fmt.Sprintf(`{"rawTx":%q,"graphID":5}`, txHex),
		"leading ws, BOM":        "\xef\xbb\xbf" + fmt.Sprintf(`{"rawTx":%q}`, txHex),
		"top-level array":        fmt.Sprintf(`[{"rawTx":%q}]`, txHex),
		"rawTx uppercase hex":    fmt.Sprintf(`{"rawTx":%q}`, strings.ToUpper(txHex)),
	}
	for name, b := range bodies {
		t.Run(name, func(t *testing.T) {
			body := []byte(b)
			guarded, consumed, gerr := decodeGASPNode(body)
			downstream, derr := gaspDownstreamDecode(body)

			if (gerr == nil) != (derr == nil) {
				t.Fatalf("decodeGASPNode err=%v, doNodeRequest's own decode err=%v -- must agree on accept or refuse", gerr, derr)
			}
			if gerr != nil {
				return // both refused: nothing more to check for this body
			}
			if !reflect.DeepEqual(guarded, downstream) {
				t.Fatalf("decodeGASPNode and doNodeRequest's own decode disagree on the same bytes:\n guard      %+v\n downstream %+v", guarded, downstream)
			}
			slicedBack, serr := gaspDownstreamDecode(consumed)
			if serr != nil {
				t.Fatalf("the consumed slice does not decode downstream: %v", serr)
			}
			if !reflect.DeepEqual(guarded, slicedBack) {
				t.Fatalf("the consumed slice decodes to a different node than the original bytes did:\n original %+v\n sliced   %+v", guarded, slicedBack)
			}
		})
	}
}
