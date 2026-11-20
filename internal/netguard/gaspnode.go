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
	"time"

	"github.com/BSVanon/Anvil/internal/netguard/bodyread"
	"github.com/BSVanon/Anvil/internal/scriptcost"
	"github.com/bsv-blockchain/go-overlay-services/pkg/core/gasp"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// GASPReadBase, GASPReadRate and GASPReadMax size the whole-read deadline a
// GASP reply (/requestForeignGASPNode or /requestSyncResponse) gets, by its
// declared length, in place of peerhygiene's flat read timeout: that timeout
// is sized for a lookup answer's 2 MiB cap, but GASP replies run up to
// MaxResponseBytes (64 MiB), where it demanded an honest peer sustain about
// 2.2 MB/s, and refused a 20 MB reply (a 10 MB transaction) from any peer
// slower than about 0.67 MB/s (cold review round 4 cycle 6b, RISK 1/2).
// gaspReadTimeout grows the deadline with the declared length instead of
// using one flat number, capped at GASPReadMax; an undeclared length (-1)
// gets the cap outright, since there is nothing to scale from. The minimum
// rate (bodyread.MinReadRate, g.minRate) is unchanged by this: it still cuts
// a peer that stops keeping up partway through, whatever this deadline
// allows in total.
const (
	GASPReadBase = 30 * time.Second
	GASPReadRate = 512 << 10 // bytes/s the deadline's growth assumes
	GASPReadMax  = 180 * time.Second
)

// gaspReadTimeout is the whole-read deadline bodyread.Read gets for a GASP
// reply declaring contentLength bytes (or -1, unknown).
func gaspReadTimeout(contentLength int64) time.Duration {
	if contentLength < 0 {
		return GASPReadMax
	}
	d := GASPReadBase + time.Duration(contentLength)*time.Second/time.Duration(GASPReadRate)
	if d > GASPReadMax {
		return GASPReadMax
	}
	return d
}

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

// isGASPSync reports whether req belongs to a GASP initial-sync request:
// OverlayGASPRemote.GetInitialResponse's POST to host + "/requestSyncResponse"
// (go-overlay-services' pkg/core/engine/gasp-remote.go), judged the same way
// isGASPNode judges its own path. Its reply has no transaction to check for
// the B1 shape, only a size, deadline and minimum rate to read it under
// (cold review round 4 cycle 6b, RISK 1): before this it fell through
// RoundTrip's generic cappedBody wrap, capped on size alone, with neither a
// deadline nor a rate floor.
func isGASPSync(req *http.Request) bool {
	req = origin(req)
	if req.Method != http.MethodPost {
		return false
	}
	return strings.HasSuffix(req.URL.Path, "/requestSyncResponse") ||
		strings.HasSuffix(req.URL.String(), "/requestSyncResponse")
}

// readGASPReply reads a GASP reply (a /requestForeignGASPNode or
// /requestSyncResponse 200) in full, up to maxBytes, under gaspReadTimeout's
// size-scaled deadline and the guard's minimum rate.
func (g *guard) readGASPReply(resp *http.Response) ([]byte, error) {
	timeout := gaspReadTimeout(resp.ContentLength)
	body, err := bodyread.Read(resp.Body, resp.ContentLength, bodyread.Limits{
		Max: g.maxBytes, Timeout: timeout, MinRate: g.minRate, Grace: g.grace,
	})
	switch {
	case err == nil:
		return body, nil
	case errors.Is(err, bodyread.ErrTooLarge):
		return nil, fmt.Errorf("%w: GASP reply is over %d bytes", ErrResponseTooLarge, g.maxBytes)
	case errors.Is(err, bodyread.ErrTimeout):
		return nil, fmt.Errorf("netguard: GASP reply not read within %v", timeout)
	case errors.Is(err, bodyread.ErrTooSlow):
		return nil, fmt.Errorf("netguard: GASP reply arrived below %d bytes/s after %v", g.minRate, g.grace)
	default:
		return nil, fmt.Errorf("netguard: reading GASP reply: %w", err)
	}
}

// checkGASPNode reads a GASP /requestForeignGASPNode reply in full, up to
// maxBytes -- the cap this traffic already had before this check existed
// (see the package doc comment, which sizes it for one transaction and its
// proof) -- under gaspReadTimeout's deadline and the guard's minimum rate
// (cold review round 4 cycle 6/6b, RISK 1).
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
// and, if clear, handed on as exactly the bytes decodeGASPNode consumed to
// produce it -- not the bytes received (a trailing byte is dropped) and not
// a re-encoding of the checked node (cold review round 4 cycle 6b's B1: a
// string field padded with '<', '>' or '&' re-encodes up to 6x larger under
// json.Marshal's HTML-escaping, for about 2 GiB of heap on one cap-sized
// reply, free for any peer at boot). Slicing the already-read bytes instead
// costs nothing extra: doNodeRequest's own identical Decode call, run again
// on that same slice downstream, reads the same node either way.
func (g *guard) checkGASPNode(resp *http.Response) (*http.Response, error) {
	body, err := g.readGASPReply(resp)
	if err != nil {
		return nil, err
	}
	node, consumed, err := decodeGASPNode(body)
	if err != nil {
		return nil, fmt.Errorf("netguard: GASP node reply did not decode: %w", err)
	}
	if reason := gaspNodeMalformed(node); reason != "" {
		return nil, fmt.Errorf("netguard: refused a GASP node reply: %s", reason)
	}
	resp.Body = io.NopCloser(bytes.NewReader(consumed))
	resp.ContentLength = int64(len(consumed))
	if resp.Header == nil {
		resp.Header = make(http.Header)
	}
	resp.Header.Set("Content-Length", strconv.Itoa(len(consumed)))
	resp.TransferEncoding = nil
	return resp, nil
}

// checkGASPSync reads a GASP /requestSyncResponse reply in full, the same
// way checkGASPNode reads its own reply (readGASPReply), and hands it on
// unchanged: GetInitialResponse's InitialResponse has no transaction, so
// there is nothing here for gaspNodeMalformed to check, only a size,
// deadline and rate to read it under (cold review round 4 cycle 6b, RISK 1).
func (g *guard) checkGASPSync(resp *http.Response) (*http.Response, error) {
	body, err := g.readGASPReply(resp)
	if err != nil {
		return nil, err
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	if resp.Header == nil {
		resp.Header = make(http.Header)
	}
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	resp.TransferEncoding = nil
	return resp, nil
}

// decodeGASPNode decodes body into a gasp.Node exactly as
// OverlayGASPRemote.doNodeRequest decodes a /requestForeignGASPNode reply:
// one json.Decoder.Decode of the first JSON value, which never errors over
// whatever follows it. The second return is body sliced to exactly the bytes
// that one Decode call consumed to produce node -- what checkGASPNode hands
// on, in place of re-encoding node (see checkGASPNode's doc comment for why).
func decodeGASPNode(body []byte) (node *gasp.Node, consumed []byte, err error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	node = &gasp.Node{}
	if err := dec.Decode(node); err != nil {
		return nil, nil, err
	}
	return node, body[:dec.InputOffset()], nil
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
