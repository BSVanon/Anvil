package netguard

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/BSVanon/Anvil/internal/netguard/bodyread"
	"github.com/BSVanon/Anvil/internal/scriptcost"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/gasp"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// isGASPNode reports whether req belongs to a GASP node fetch: a POST to a
// URL that OverlayGASPRemote.doNodeRequest (go-overlay-services'
// pkg/core/engine/gasp-remote.go) builds as host + "/requestForeignGASPNode",
// judged by its origin, by isLookup's rules. X-BSV-Topic, the header that
// file sets on its requests, is not a usable marker here: doNodeRequest and
// GetInitialResponse both set it, and GetInitialResponse's reply
// (/requestSyncResponse) carries no raw transaction and needs no check of
// this kind, so the path is matched on its own.
func isGASPNode(req *http.Request) bool {
	req = origin(req)
	if req.Method != http.MethodPost {
		return false
	}
	return strings.HasSuffix(req.URL.Path, "/requestForeignGASPNode") ||
		strings.HasSuffix(req.URL.String(), "/requestForeignGASPNode")
}

// checkGASPNode reads a GASP /requestForeignGASPNode reply in full, up to
// maxBytes -- the cap this traffic already had before this check existed
// (see the package doc comment, which sizes it for one transaction and its
// proof) -- under the same read deadline and minimum rate checkLookup's
// replies read under: GASP sync runs one peer at a time, so a slow peer
// stalled every later topic with no bound before this (cold review round 4
// cycle 6, RISK 1).
//
// It then decodes the body exactly as OverlayGASPRemote.doNodeRequest itself
// will (go-overlay-services pkg/core/engine/gasp-remote.go:184): one
// json.Decoder.Decode of the first JSON value -- the same call doNodeRequest
// makes on resp.Body, made here first, on the bytes already read. Matching
// that decode, rather than json.Unmarshal's stricter whole-body parse this
// check used before, is what closes cold review round 4 cycle 6's B1:
// Unmarshal fails -- and the old code handed the reply on unchecked, fail
// open -- for a reply doNodeRequest decodes cleanly, such as one JSON object
// followed by a trailing byte, a second object, "]" or a NUL: free for a
// hostile peer to append. A reply that does not decode even that way is
// refused outright, fail closed: doNodeRequest's own identical Decode call
// would fail on the same bytes too, so this never refuses a reply the real
// decode would have accepted, only moves an inevitable failure to this one
// exchange instead of leaving doNodeRequest to hit it moments later.
//
// The decoded node is checked for the one confirmed shape (gaspNodeMalformed)
// and, if clear, re-encoded: the caller is handed on exactly the node
// checked, not the bytes received, so nothing past what was decoded and
// checked -- a trailing byte included -- ever reaches doNodeRequest's own
// Decode call.
func (g *guard) checkGASPNode(resp *http.Response) (*http.Response, error) {
	body, err := bodyread.Read(resp.Body, resp.ContentLength, bodyread.Limits{
		Max: g.maxBytes, Timeout: g.readTimeout, MinRate: g.minRate, Grace: g.grace,
	})
	switch {
	case err == nil:
	case errors.Is(err, bodyread.ErrTooLarge):
		return nil, fmt.Errorf("%w: GASP node reply is over %d bytes", ErrResponseTooLarge, g.maxBytes)
	case errors.Is(err, bodyread.ErrTimeout):
		return nil, fmt.Errorf("netguard: GASP node reply not read within %v", g.readTimeout)
	case errors.Is(err, bodyread.ErrTooSlow):
		return nil, fmt.Errorf("netguard: GASP node reply arrived below %d bytes/s after %v", g.minRate, g.grace)
	default:
		return nil, fmt.Errorf("netguard: reading GASP node reply: %w", err)
	}
	node, err := decodeGASPNode(body)
	if err != nil {
		return nil, fmt.Errorf("netguard: GASP node reply did not decode: %w", err)
	}
	if reason := gaspNodeMalformed(node); reason != "" {
		return nil, fmt.Errorf("netguard: refused a GASP node reply: %s", reason)
	}
	out, err := json.Marshal(node)
	if err != nil {
		return nil, fmt.Errorf("netguard: re-encoding GASP node reply: %w", err)
	}
	resp.Body = io.NopCloser(bytes.NewReader(out))
	resp.ContentLength = int64(len(out))
	if resp.Header == nil {
		resp.Header = make(http.Header)
	}
	resp.Header.Set("Content-Length", strconv.Itoa(len(out)))
	resp.TransferEncoding = nil
	return resp, nil
}

// decodeGASPNode decodes body into a gasp.Node exactly as
// OverlayGASPRemote.doNodeRequest decodes a /requestForeignGASPNode reply:
// one json.Decoder.Decode of the first JSON value, which never errors over
// whatever follows it. See checkGASPNode.
func decodeGASPNode(body []byte) (*gasp.Node, error) {
	var node gasp.Node
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&node); err != nil {
		return nil, err
	}
	return &node, nil
}

// parseGASPTransaction is transaction.NewTransactionFromBytes, held in a
// variable so a test can make it panic and confirm the recover in
// gaspNodeMalformed (cold review round 4 cycle 6, RISK 3) turns that into a
// refusal instead of reaching Sync's errgroup goroutine, which nothing above
// RequestNode recovers.
var parseGASPTransaction = transaction.NewTransactionFromBytes

// gaspNodeMalformed reports why node, decoded from a /requestForeignGASPNode
// reply, should be refused, or "" to hand it on. Anything this cannot read
// as hex or as a transaction is handed on too (""): this check only ever
// adds a refusal for one confirmed shape, never a stricter GASP decoder than
// doNodeRequest's own.
//
// A node carrying a Proof is never checked (cold review round 4 cycle 6,
// RISK 4): ValidateGraphAnchor's spv.Verify accepts a transaction a merkle
// path proves mined without ever running its scripts (go-sdk v1.7.7
// spv/verify.go's doc comment: "A transaction with a merkle path is
// accepted once chainTracker confirms the path"; verifyUnmined stops at a
// proven txid before calling verifyTx). The B1 reparse trigger this function
// looks for needs a script to run, so it can never fire for a proven node --
// refusing one anyway would block syncing an on-chain-valid graph over a
// shape that is harmless once mined, such as a mined Chronicle transaction
// with a top-level OP_RETURN followed by a tail that only looks malformed.
//
// Parsing node.RawTx and walking its inputs runs under netguard.Contain
// (cold review round 4 cycle 6, RISK 3): an untrusted hex string reaching
// go-sdk's transaction parser with no recover of its own must not be able to
// end the process from this goroutine. A panic there is treated as a
// confirmed malformed shape -- refused, fail closed -- and logged by Contain
// with its site and stack for attribution.
func gaspNodeMalformed(node *gasp.Node) string {
	if node.RawTx == "" || (node.Proof != nil && *node.Proof != "") {
		return ""
	}
	var reason string
	if err := Contain(nil, "netguard.gaspNodeMalformed", func() error {
		raw, err := hex.DecodeString(node.RawTx)
		if err != nil {
			return nil
		}
		tx, err := parseGASPTransaction(raw)
		if err != nil || tx == nil {
			return nil
		}
		for vin, in := range tx.Inputs {
			if in.UnlockingScript != nil && scriptcost.EndsMalformed(*in.UnlockingScript) {
				reason = fmt.Sprintf("input %d of %s ends in an undecodable instruction", vin, tx.TxID())
				return nil
			}
		}
		return nil
	}); err != nil {
		return fmt.Sprintf("the node's transaction could not be safely checked: %v", err)
	}
	return reason
}
