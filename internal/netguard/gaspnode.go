package netguard

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
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
// proof) -- and refuses it when the transaction it carries has an input
// whose unlocking script ends in an undecodable instruction
// (scriptcost.EndsMalformed). That is the B1 shape (cold review round 4): it
// lets a signature opcode's reparse of the unlocking script joined with the
// spent locking script explode into one ParsedOpcode per byte of a huge
// locking script (go-sdk v1.7.7, script/interpreter/thread.go:1123-1162).
// ValidateGraphAnchor (go-overlay-services pkg/core/engine/gasp-storage.go)
// runs spv.Verify on every node a GASP sync accepts, with no check of this
// kind anywhere in that vendored path, so this is the only place Anvil's own
// code can refuse it before that happens, from a hostile SHIP-advertised
// peer's reply, without forking go-overlay-services: NewOverlayGASPRemote is
// built with http.DefaultClient (engine.go:1129 and :1209), the very client
// Install wraps.
//
// Unlike checkLookup, nothing here is re-encoded: an accepted reply is handed
// on as exactly the bytes read, so OverlayGASPRemote.doNodeRequest's own
// json.Decoder sees exactly what a peer sent. A reply this cannot read as a
// gasp.Node, as hex, or as a transaction is handed on unchanged too: this
// check only ever adds a refusal for one confirmed shape, never a stricter
// GASP decoder than doNodeRequest's own, so a parsing difference between the
// two can never refuse a reply that decoder would have accepted. A refusal
// here fails only the one HTTP exchange doNodeRequest made -- an error
// RoundTrip returns, exactly as a network failure would -- so
// GASP.CompleteGraph abandons that graph and the sync moves on; one hostile
// peer's reply never reaches another peer's sync.
//
// This read has no deadline or minimum rate, unlike checkLookup's: the
// generic cappedBody path this traffic fell through before this check
// existed had neither either, so a slow peer is no worse off than before.
func (g *guard) checkGASPNode(resp *http.Response) (*http.Response, error) {
	body, err := bodyread.Read(resp.Body, resp.ContentLength, bodyread.Limits{Max: g.maxBytes})
	switch {
	case err == nil:
	case errors.Is(err, bodyread.ErrTooLarge):
		return nil, fmt.Errorf("%w: GASP node reply is over %d bytes", ErrResponseTooLarge, g.maxBytes)
	default:
		return nil, fmt.Errorf("netguard: reading GASP node reply: %w", err)
	}
	if reason := gaspNodeMalformed(body); reason != "" {
		return nil, fmt.Errorf("netguard: refused a GASP node reply: %s", reason)
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return resp, nil
}

// gaspNodeMalformed reports why body, a /requestForeignGASPNode reply,
// should be refused, or "" to hand it on unchanged -- including when it
// cannot be read as a gasp.Node, as hex, or as a transaction (see
// checkGASPNode).
func gaspNodeMalformed(body []byte) string {
	var node gasp.Node
	if err := json.Unmarshal(body, &node); err != nil || node.RawTx == "" {
		return ""
	}
	raw, err := hex.DecodeString(node.RawTx)
	if err != nil {
		return ""
	}
	tx, err := transaction.NewTransactionFromBytes(raw)
	if err != nil || tx == nil {
		return ""
	}
	for vin, in := range tx.Inputs {
		if in.UnlockingScript != nil && scriptcost.EndsMalformed(*in.UnlockingScript) {
			return fmt.Sprintf("input %d of %s ends in an undecodable instruction", vin, tx.TxID())
		}
	}
	return ""
}
