package netguard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"

	"github.com/bsv-blockchain/go-sdk/chainhash"
	"github.com/bsv-blockchain/go-sdk/overlay"
)

// The smallest wire encodings, from which the size of a request bounds the
// indices its transaction can have.
const (
	// minOutputBytes is an output's 8-byte value and a script-length varint
	// of at least 1 byte.
	minOutputBytes = 8 + 1
	// minInputBytes is an input's 32-byte txid, 4-byte output index,
	// script-length varint of at least 1 byte and 4-byte sequence.
	minInputBytes = 32 + 4 + 1 + 4
	// minTxBytes is a transaction's 4-byte version, input and output count
	// varints of at least 1 byte each and 4-byte lock time.
	minTxBytes = 4 + 1 + 1 + 4
	// maxUnnamedTopics caps the topics a STEAK may list when its request
	// named none in X-Topics, which go-sdk's facilitator always sets, so only
	// some other caller's request can lack it. A STEAK lists the topics its
	// request was submitted to: Anvil hosts nine topic managers, and 64 is
	// several times what any one submit names.
	maxUnnamedTopics = 64
)

// The fields of go-sdk's overlay.AdmittanceInstructions, by their JSON names.
const (
	fieldOutputsToAdmit = "outputsToAdmit"
	fieldCoinsToRetain  = "coinsToRetain"
	fieldCoinsRemoved   = "coinsRemoved"
	fieldAncillaryTxids = "ancillaryTxids"
)

var steakFields = []string{fieldOutputsToAdmit, fieldCoinsToRetain, fieldCoinsRemoved, fieldAncillaryTxids}

// steakBounds are what a STEAK may hold, given the request it answers.
type steakBounds struct {
	topics  map[string]bool // the topics the request named in X-Topics; nil if it named none
	outputs uint64          // every output index is below this, and no list of them is longer
	inputs  uint64          // every coin index (an input's) is below this, and no list of them is longer
	txids   int             // the most ancillary txids one topic may list
}

// boundsFor derives a STEAK's bounds from the request that started its
// exchange. go-sdk's facilitator sends the transaction's Atomic BEEF with its
// length declared, and names the topics in X-Topics as a JSON array. The
// transaction lies within the n-byte body, so it has fewer than n/9 outputs
// and n/41 inputs, and the BEEF holds at most n/10 transactions. A body of
// unknown length bounds indices only to uint32, and MaxSteakBytes bounds the
// lists.
func boundsFor(req *http.Request) steakBounds {
	b := steakBounds{outputs: math.MaxUint32 + 1, inputs: math.MaxUint32 + 1, txids: math.MaxInt}
	if n := req.ContentLength; n > 0 {
		b.outputs = uint64(n) / minOutputBytes
		b.inputs = uint64(n) / minInputBytes
		b.txids = int(n / minTxBytes)
	}
	var topics []string
	if json.Unmarshal([]byte(req.Header.Get("X-Topics")), &topics) == nil && len(topics) > 0 {
		b.topics = make(map[string]bool, len(topics))
		for _, t := range topics {
			b.topics[t] = true
		}
	}
	return b
}

// decodeSteak decodes a /submit reply into the STEAK go-sdk's Broadcaster
// may read, or fails. The reply must be a JSON object; each topic the request
// named must map to an object, never null; each index list must be null or
// an array of integer indices within bounds. Fields are matched as
// encoding/json matches them, ignoring case, and fields go-sdk does not know
// are skipped. A topic the request did not name is skipped too: go-sdk's
// Broadcaster counts acknowledgements only for the topics it sent. A topic or
// field given twice is refused, where encoding/json would keep the last.
// Like go-sdk's decoder, it reads the first JSON value and ignores the rest.
func decodeSteak(body []byte, b steakBounds) (overlay.Steak, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := expectDelim(dec, '{', "the reply"); err != nil {
		return nil, err
	}
	steak := overlay.Steak{}
	for dec.More() {
		topic, err := objectKey(dec)
		if err != nil {
			return nil, err
		}
		if b.topics != nil && !b.topics[topic] {
			if err := skipValue(dec); err != nil {
				return nil, err
			}
			continue
		}
		if _, dup := steak[topic]; dup {
			return nil, fmt.Errorf("topic %q is listed twice", topic)
		}
		if b.topics == nil && len(steak) == maxUnnamedTopics {
			return nil, fmt.Errorf("the reply lists more than %d topics", maxUnnamedTopics)
		}
		inst, err := decodeInstructions(dec, topic, b)
		if err != nil {
			return nil, err
		}
		steak[topic] = inst
	}
	if err := expectDelim(dec, '}', "the reply"); err != nil {
		return nil, err
	}
	return steak, nil
}

func decodeInstructions(dec *json.Decoder, topic string, b steakBounds) (*overlay.AdmittanceInstructions, error) {
	if err := expectDelim(dec, '{', fmt.Sprintf("topic %q", topic)); err != nil {
		return nil, err
	}
	inst := &overlay.AdmittanceInstructions{}
	seen := make(map[string]bool, len(steakFields))
	for dec.More() {
		name, err := objectKey(dec)
		if err != nil {
			return nil, err
		}
		field := knownField(name)
		if field == "" {
			if err := skipValue(dec); err != nil {
				return nil, err
			}
			continue
		}
		if seen[field] {
			return nil, fmt.Errorf("topic %q lists %s twice", topic, field)
		}
		seen[field] = true
		where := fmt.Sprintf("topic %q %s", topic, field)
		switch field {
		case fieldOutputsToAdmit:
			inst.OutputsToAdmit, err = decodeIndices(dec, where, b.outputs, "outputs")
		case fieldCoinsToRetain:
			inst.CoinsToRetain, err = decodeIndices(dec, where, b.inputs, "inputs")
		case fieldCoinsRemoved:
			inst.CoinsRemoved, err = decodeIndices(dec, where, b.inputs, "inputs")
		case fieldAncillaryTxids:
			inst.AncillaryTxids, err = decodeTxids(dec, where, b.txids)
		}
		if err != nil {
			return nil, err
		}
	}
	if err := expectDelim(dec, '}', fmt.Sprintf("topic %q", topic)); err != nil {
		return nil, err
	}
	return inst, nil
}

// knownField returns the AdmittanceInstructions field a JSON key decodes into,
// matched as encoding/json matches it (its fold equals strings.EqualFold), or
// "" for a key go-sdk ignores.
func knownField(name string) string {
	for _, f := range steakFields {
		if strings.EqualFold(name, f) {
			return f
		}
	}
	return ""
}

// decodeIndices decodes a list of indices, each below bound, of which there
// can be no more than bound. JSON null decodes to a nil list, as go-sdk
// decodes it; a list's elements must be integers that fit a uint32.
func decodeIndices(dec *json.Decoder, where string, bound uint64, of string) ([]uint32, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", where, err)
	}
	if tok == nil {
		return nil, nil
	}
	if tok != json.Delim('[') {
		return nil, fmt.Errorf("%s is %s, not a list", where, describe(tok))
	}
	list := []uint32{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", where, err)
		}
		num, ok := tok.(json.Number)
		if !ok {
			return nil, fmt.Errorf("%s holds %s, not an index", where, describe(tok))
		}
		v, err := strconv.ParseUint(string(num), 10, 32)
		if err != nil {
			return nil, fmt.Errorf("%s holds %s, not a uint32 index", where, num)
		}
		if uint64(v) >= bound {
			return nil, fmt.Errorf("%s holds index %d; the request's transaction has fewer than %d %s", where, v, bound, of)
		}
		if uint64(len(list)) == bound {
			return nil, fmt.Errorf("%s lists more than the %d %s the request's transaction can have", where, bound, of)
		}
		list = append(list, uint32(v))
	}
	if err := expectDelim(dec, ']', where); err != nil {
		return nil, err
	}
	return list, nil
}

// decodeTxids decodes a list of at most bound txids, each read as go-sdk's
// chainhash.Hash reads one.
func decodeTxids(dec *json.Decoder, where string, bound int) ([]*chainhash.Hash, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", where, err)
	}
	if tok == nil {
		return nil, nil
	}
	if tok != json.Delim('[') {
		return nil, fmt.Errorf("%s is %s, not a list", where, describe(tok))
	}
	list := []*chainhash.Hash{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", where, err)
		}
		s, ok := tok.(string)
		if !ok {
			return nil, fmt.Errorf("%s holds %s, not a txid", where, describe(tok))
		}
		h, err := chainhash.NewHashFromHex(s)
		if err != nil {
			return nil, fmt.Errorf("%s holds %q, not a txid: %w", where, s, err)
		}
		if len(list) == bound {
			return nil, fmt.Errorf("%s lists more than the %d transactions the request can carry", where, bound)
		}
		list = append(list, h)
	}
	if err := expectDelim(dec, ']', where); err != nil {
		return nil, err
	}
	return list, nil
}

// objectKey reads the next key of the object being decoded.
func objectKey(dec *json.Decoder) (string, error) {
	tok, err := dec.Token()
	if err != nil {
		return "", err
	}
	key, ok := tok.(string)
	if !ok {
		return "", fmt.Errorf("unexpected %s for an object key", describe(tok))
	}
	return key, nil
}

// expectDelim reads the next token, which must be want.
func expectDelim(dec *json.Decoder, want json.Delim, what string) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	if tok != want {
		if want == '{' {
			return fmt.Errorf("%s is %s, not an object", what, describe(tok))
		}
		return fmt.Errorf("%s: unexpected %s", what, describe(tok))
	}
	return nil
}

// skipValue reads and drops the next value, which must be well-formed JSON.
func skipValue(dec *json.Decoder) error {
	var skipped json.RawMessage
	if err := dec.Decode(&skipped); err != nil {
		return err
	}
	return nil
}

// describe names a JSON token's kind for an error message.
func describe(tok json.Token) string {
	switch v := tok.(type) {
	case nil:
		return "null"
	case json.Delim:
		if v == '[' {
			return "a list"
		}
		if v == '{' {
			return "an object"
		}
		return fmt.Sprintf("%q", string(v))
	case string:
		return "a string"
	case json.Number:
		return "a number"
	case bool:
		return "a boolean"
	default:
		return fmt.Sprintf("%T", tok)
	}
}
