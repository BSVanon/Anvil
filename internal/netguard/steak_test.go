package netguard

import (
	"bytes"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/bsv-blockchain/go-sdk/overlay"
)

const someTxid = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"

// steakRequest is a /submit request as go-sdk's facilitator builds it: a
// declared body of n bytes and the topics in X-Topics as a JSON array, or no
// X-Topics when topics is nil.
func steakRequest(t *testing.T, n int, topics ...string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, "http://h/submit", bytes.NewReader(make([]byte, n)))
	if err != nil {
		t.Fatal(err)
	}
	if topics != nil {
		b, _ := json.Marshal(topics)
		req.Header.Set("X-Topics", string(b))
	}
	return req
}

// goSDKDecode decodes a reply as go-sdk's broadcast facilitator does.
func goSDKDecode(t *testing.T, body []byte) *overlay.Steak {
	t.Helper()
	steak := &overlay.Steak{}
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&steak); err != nil {
		t.Fatalf("go-sdk's decoder refuses %s: %v", body, err)
	}
	return steak
}

// TestDecodeSteak_AcceptsHonestShapes: the STEAK shapes honest peers send
// (go-sdk's own encoding, the TypeScript overlay's, Anvil's canonical and
// legacy /submit replies, untagged Go field names, unknown fields, trailing
// data) decode as go-sdk decodes them, except that topics the request did not
// name are dropped. Re-encoded, go-sdk decodes the result to the same STEAK,
// with no nil entry anywhere.
func TestDecodeSteak_AcceptsHonestShapes(t *testing.T) {
	req := steakRequest(t, 1000, "tm_a", "tm_b")
	for _, tc := range []struct {
		name, body string
		drop       []string // topics go-sdk keeps that the request did not name
	}{
		{"go-sdk encoding", `{"tm_a":{"outputsToAdmit":[0,2],"coinsToRetain":null,"ancillaryTxids":["` + someTxid + `"]}}`, nil},
		{"TypeScript overlay", `{"tm_a":{"outputsToAdmit":[1],"coinsToRetain":[0],"coinsRemoved":[1]},"tm_b":{"outputsToAdmit":[],"coinsToRetain":[]}}`, nil},
		{"Anvil canonical", `{"tm_a":{"outputsToAdmit":[0],"coinsToRetain":[],"coinsRemoved":[],"ancillaryTxIDs":[]}}`, nil},
		{"Anvil legacy", `{"tm_a":{"outputsToAdmit":[0],"coinsToRetain":null}}`, nil},
		{"untagged Go names", `{"tm_a":{"OutputsToAdmit":[3],"CoinsToRetain":[1],"AncillaryTxids":null}}`, nil},
		{"unknown fields", `{"tm_a":{"outputsToAdmit":[0],"extra":{"deep":[1,"x",{"n":null}]},"note":null}}`, nil},
		{"empty", `{}`, nil},
		{"trailing data", `{"tm_a":{"outputsToAdmit":[0]}} and then anything`, nil},
		{"a topic the request did not name", `{"tm_other":{"outputsToAdmit":[0]},"tm_a":{"outputsToAdmit":[0]}}`, []string{"tm_other"}},
		{"go-overlay-services wrapper", `{"STEAK":{"tm_a":{"outputsToAdmit":[0]}}}`, []string{"STEAK"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeSteak([]byte(tc.body), boundsFor(req))
			if err != nil {
				t.Fatalf("decodeSteak refused an honest reply: %v", err)
			}
			want := *goSDKDecode(t, []byte(tc.body))
			for _, topic := range tc.drop {
				delete(want, topic)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("decodeSteak differs from go-sdk:\n got  %s\n want %s", dump(got), dump(want))
			}
			out, err := json.Marshal(got)
			if err != nil {
				t.Fatalf("re-encode: %v", err)
			}
			again := *goSDKDecode(t, out)
			if !sameSteak(again, got) {
				t.Fatalf("go-sdk decodes the re-encoding differently:\n got  %s\n want %s", dump(again), dump(got))
			}
		})
	}
}

// sameSteak reports whether go-sdk's Broadcaster reads a and b alike: the same
// topics, none nil, and the same indices and txids. A nil list and an empty
// one differ only for outputsToAdmit and coinsToRetain, which go-sdk encodes
// as null and []; coinsRemoved and ancillaryTxids are omitted when empty, so
// either decodes to nil, and go-sdk reads every list only by its length.
func sameSteak(a, b overlay.Steak) bool {
	if len(a) != len(b) {
		return false
	}
	for topic, x := range a {
		y, ok := b[topic]
		if !ok || x == nil || y == nil {
			return false
		}
		if !reflect.DeepEqual(x.OutputsToAdmit, y.OutputsToAdmit) || !reflect.DeepEqual(x.CoinsToRetain, y.CoinsToRetain) {
			return false
		}
		if len(x.CoinsRemoved) != len(y.CoinsRemoved) || (len(x.CoinsRemoved) > 0 && !reflect.DeepEqual(x.CoinsRemoved, y.CoinsRemoved)) {
			return false
		}
		if len(x.AncillaryTxids) != len(y.AncillaryTxids) {
			return false
		}
		for i := range x.AncillaryTxids {
			if !x.AncillaryTxids[i].IsEqual(y.AncillaryTxids[i]) {
				return false
			}
		}
	}
	return true
}

func dump(s overlay.Steak) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// TestDecodeSteak_RefusesWhatGoSDKCannotSurvive: every reply below either
// panics go-sdk's Broadcaster (null where it dereferences), fails its decoder
// (a type it cannot decode), or names more than the request's transaction can
// have. Each is refused, naming why.
func TestDecodeSteak_RefusesWhatGoSDKCannotSurvive(t *testing.T) {
	// A 100-byte request: fewer than 11 outputs, 2 inputs and 10 transactions.
	named := boundsFor(steakRequest(t, 100, "tm_a"))
	unnamed := boundsFor(steakRequest(t, 100))
	many := `{`
	for i := range maxUnnamedTopics + 1 {
		if i > 0 {
			many += ","
		}
		many += `"tm_` + strings.Repeat("z", i+1) + `":{}`
	}
	many += `}`
	for _, tc := range []struct {
		name, body string
		bounds     steakBounds
		want       string
	}{
		{"top-level null", `null`, named, "the reply is null, not an object"},
		{"top-level list", `[]`, named, "the reply is a list, not an object"},
		{"top-level string", `"steak"`, named, "the reply is a string, not an object"},
		{"top-level number", `5`, named, "the reply is a number, not an object"},
		{"empty body", ``, named, "the reply: EOF"},
		{"topic null", `{"tm_a":null}`, named, `topic "tm_a" is null, not an object`},
		{"topic list", `{"tm_a":[0]}`, named, `topic "tm_a" is a list, not an object`},
		{"topic number", `{"tm_a":1}`, named, `topic "tm_a" is a number, not an object`},
		{"unnamed topic null", `{"tm_a":null}`, unnamed, `topic "tm_a" is null, not an object`},
		{"index list a number", `{"tm_a":{"outputsToAdmit":5}}`, named, "outputsToAdmit is a number, not a list"},
		{"index list a string", `{"tm_a":{"coinsToRetain":"0"}}`, named, "coinsToRetain is a string, not a list"},
		{"negative index", `{"tm_a":{"outputsToAdmit":[-1]}}`, named, "holds -1, not a uint32 index"},
		{"fractional index", `{"tm_a":{"outputsToAdmit":[1.5]}}`, named, "holds 1.5, not a uint32 index"},
		{"exponent index", `{"tm_a":{"outputsToAdmit":[1e2]}}`, named, "holds 1e2, not a uint32 index"},
		{"index over uint32", `{"tm_a":{"outputsToAdmit":[4294967296]}}`, unnamed, "holds 4294967296, not a uint32 index"},
		{"null index", `{"tm_a":{"outputsToAdmit":[null]}}`, named, "holds null, not an index"},
		{"string index", `{"tm_a":{"coinsRemoved":["0"]}}`, named, "holds a string, not an index"},
		{"object index", `{"tm_a":{"outputsToAdmit":[{}]}}`, named, "holds an object, not an index"},
		{"output index past the outputs", `{"tm_a":{"outputsToAdmit":[11]}}`, named, "holds index 11; the request's transaction has fewer than 11 outputs"},
		{"more outputs than there can be", `{"tm_a":{"outputsToAdmit":[0,0,0,0,0,0,0,0,0,0,0,0]}}`, named, "lists more than the 11 outputs"},
		{"coin index past the inputs", `{"tm_a":{"coinsToRetain":[2]}}`, named, "holds index 2; the request's transaction has fewer than 2 inputs"},
		{"removed coin past the inputs", `{"tm_a":{"coinsRemoved":[7]}}`, named, "holds index 7; the request's transaction has fewer than 2 inputs"},
		{"txid not hex", `{"tm_a":{"ancillaryTxids":["zz"]}}`, named, `holds "zz", not a txid`},
		{"txid too long", `{"tm_a":{"ancillaryTxids":["` + someTxid + `00"]}}`, named, "not a txid"},
		{"txid a number", `{"tm_a":{"ancillaryTxids":[5]}}`, named, "holds a number, not a txid"},
		{"txid null", `{"tm_a":{"ancillaryTxids":[null]}}`, named, "holds null, not a txid"},
		{"more txids than transactions", `{"tm_a":{"ancillaryTxids":[` + strings.TrimSuffix(strings.Repeat(`"`+someTxid+`",`, 11), ",") + `]}}`, named, "lists more than the 10 transactions"},
		{"topic twice", `{"tm_a":{},"tm_a":{}}`, named, `topic "tm_a" is listed twice`},
		{"field twice, case folded", `{"tm_a":{"outputsToAdmit":[0],"OUTPUTSTOADMIT":[1]}}`, named, "lists outputsToAdmit twice"},
		{"truncated", `{"tm_a":{"outputsToAdmit":[0`, named, "outputsToAdmit: EOF"},
		{"malformed", `{"tm_a" 5}`, named, "invalid character"},
		{"malformed skipped value", `{"tm_other":{"x":[1,}}`, named, "invalid character"},
		{"too many unnamed topics", many, unnamed, "the reply lists more than 64 topics"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeSteak([]byte(tc.body), tc.bounds)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want an error containing %q, got %v (decoded %s)", tc.want, err, dump(got))
			}
		})
	}
}

// TestBoundsFor: the bounds come from the request: indices below n/9 outputs
// and n/41 inputs, at most n/10 txids, the topics of a JSON X-Topics header,
// and no topic set, nor any index bound past uint32, when the request does
// not say.
func TestBoundsFor(t *testing.T) {
	b := boundsFor(steakRequest(t, 4100, "tm_a", "tm_b"))
	if b.outputs != 455 || b.inputs != 100 || b.txids != 410 {
		t.Fatalf("a 4,100-byte request: outputs %d, inputs %d, txids %d; want 455, 100, 410", b.outputs, b.inputs, b.txids)
	}
	if !reflect.DeepEqual(b.topics, map[string]bool{"tm_a": true, "tm_b": true}) {
		t.Fatalf("topics %v, want tm_a and tm_b", b.topics)
	}
	req := steakRequest(t, 0)
	req.ContentLength = -1
	req.Header.Set("X-Topics", "tm_a,tm_b") // not a JSON array
	b = boundsFor(req)
	if b.topics != nil || b.outputs != 1<<32 || b.inputs != 1<<32 {
		t.Fatalf("a request of unknown length and unparsable topics: %+v", b)
	}
}
