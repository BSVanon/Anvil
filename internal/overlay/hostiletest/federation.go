package hostiletest

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bsv-blockchain/go-sdk/overlay/lookup"
	"github.com/bsv-blockchain/go-sdk/script"
	"github.com/bsv-blockchain/go-sdk/transaction"
)

// SteakReply is how a SteakPeer answers POST /submit.
type SteakReply struct {
	// Body is the reply.
	Body *Reply
	// Streamed sends Body with no Content-Length, flushed as it is written,
	// so a reader cannot refuse it by a declared length.
	Streamed bool
	// Rate, when above zero, sends Body and then JSON whitespace at Rate
	// bytes a second, a tenth of a second at a time, until the reader lets
	// go: a reply that never ends.
	Rate int
}

// SteakPeer is a federation peer as a propagating engine finds it through a
// SLAP tracker: asked for ls_slap it advertises itself for ls_ship, asked for
// ls_ship it advertises itself for one topic, and it answers every POST
// /submit, an engine propagating a transaction it admitted, with a canned
// reply. An engine reaches it with the peer's URL as its only SLAP tracker.
type SteakPeer struct {
	URL     string
	submits atomic.Int64
	writing atomic.Int64
}

// NewSteakPeer starts a peer for topic that answers every submit with r.
func NewSteakPeer(t testing.TB, topic string, r SteakReply) *SteakPeer {
	t.Helper()
	p := &SteakPeer{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(req.Body, 1<<20))
		if strings.HasSuffix(req.URL.Path, "/lookup") {
			p.lookup(w, body, topic)
			return
		}
		p.submits.Add(1)
		p.writing.Add(1)
		defer p.writing.Add(-1)
		p.submit(w, req, r)
	}))
	t.Cleanup(srv.Close)
	p.URL = srv.URL
	return p
}

// Submits is how many POST /submit requests reached the peer.
func (p *SteakPeer) Submits() int64 { return p.submits.Load() }

// Writing is how many /submit replies the peer is still writing. It drops to
// zero once each reader has read its reply or let go of the connection.
func (p *SteakPeer) Writing() int64 { return p.writing.Load() }

func (p *SteakPeer) lookup(w http.ResponseWriter, question []byte, topic string) {
	var q struct {
		Service string `json:"service"`
	}
	_ = json.Unmarshal(question, &q)
	ad := shipAd(p.URL, topic)
	if q.Service == "ls_slap" {
		ad = slapAd(p.URL)
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(outputList(ad))
}

// SLAPAnswer is the JSON answer to an ls_slap query that advertises host for
// ls_ship, as a SLAP tracker gives it.
func SLAPAnswer(host string) []byte { return outputList(slapAd(host)) }

// outputList is a JSON lookup answer listing ad's only output.
func outputList(ad *transaction.Transaction) []byte {
	answer, err := json.Marshal(&lookup.LookupAnswer{
		Type:    lookup.AnswerTypeOutputList,
		Outputs: []*lookup.OutputListItem{{Beef: beefOf(ad), OutputIndex: 0}},
	})
	if err != nil {
		panic(err) // a lookup answer of bytes and an index always marshals
	}
	return answer
}

func (p *SteakPeer) submit(w http.ResponseWriter, req *http.Request, r SteakReply) {
	w.Header().Set("Content-Type", r.Body.ContentType)
	open := r.Streamed || r.Rate > 0
	if !open {
		w.Header().Set("Content-Length", strconv.FormatInt(r.Body.Len(), 10))
	}
	w.WriteHeader(http.StatusOK)
	flush := func() {
		if f, ok := w.(http.Flusher); ok && open {
			f.Flush()
		}
	}
	if _, err := r.Body.WriteTo(w); err != nil || r.Rate <= 0 {
		return
	}
	flush()
	space := bytes.Repeat([]byte(" "), max(1, r.Rate/10))
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-req.Context().Done():
			return
		case <-tick.C:
		}
		if _, err := w.Write(space); err != nil {
			return
		}
		flush()
	}
}

// shipAd returns a transaction with no inputs whose one output advertises
// host for topic over SHIP, as go-sdk's admintoken.Decode reads it.
func shipAd(host, topic string) *transaction.Transaction {
	s := &script.Script{}
	_ = s.AppendPushData(generator)
	_ = s.AppendOpcodes(script.OpCHECKSIG)
	for _, field := range []string{"SHIP", string(generator), host, topic} {
		_ = s.AppendPushData([]byte(field))
	}
	_ = s.AppendOpcodes(script.Op2DROP, script.Op2DROP)
	return plainTx(1, s)
}

// Logs holds what slog's default logger writes during a test, where the
// overlay engine logs a failed propagation.
type Logs struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

// WatchLogs points slog's default logger, and with it the log package, at a
// new Logs until the test ends.
func WatchLogs(t testing.TB) *Logs {
	t.Helper()
	l := &Logs{}
	previous, out, flags := slog.Default(), log.Writer(), log.Flags()
	t.Cleanup(func() {
		slog.SetDefault(previous)
		log.SetOutput(out) // SetDefault does not restore what it redirected
		log.SetFlags(flags)
	})
	slog.SetDefault(slog.New(slog.NewTextHandler(l, nil)))
	return l
}

func (l *Logs) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

// Line waits up to wait for a logged line holding every one of parts and
// returns it, or "" if none came. Looking allocates nothing, so a test can
// count what the code it waits on allocates.
func (l *Logs) Line(wait time.Duration, parts ...string) string {
	want := make([][]byte, len(parts))
	for i, part := range parts {
		want[i] = []byte(part)
	}
	for end := time.Now().Add(wait); ; time.Sleep(10 * time.Millisecond) {
		if line := l.find(want); line != "" || time.Now().After(end) {
			return line
		}
	}
}

func (l *Logs) find(want [][]byte) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	for rest := l.buf.Bytes(); len(rest) > 0; {
		line := rest
		if i := bytes.IndexByte(rest, '\n'); i >= 0 {
			line, rest = rest[:i], rest[i+1:]
		} else {
			rest = nil
		}
		found := true
		for _, part := range want {
			found = found && bytes.Contains(line, part)
		}
		if found {
			return string(line)
		}
	}
	return ""
}

// SteakCase is one /submit reply a SteakPeer gives.
type SteakCase struct {
	Name  string
	Reply SteakReply
	// Accepted is set for a reply a guarded client must hand on, so the
	// propagation to the peer succeeds. Every other reply must fail it.
	Accepted bool
	// Oversize is set for a reply far past any cap, so a test bounds the
	// heap reading it takes.
	Oversize bool
}

// SteakCases are the replies to a submit that named topic, and only topic,
// that a guarded propagation is tested with: replies go-sdk's Broadcaster
// cannot survive (null where it dereferences, topic/broadcaster.go:177 and
// :178), cannot decode, should not trust, cannot hold, or would wait on, then
// two it must accept. The last hides a null under a topic the request did not
// name, which go-sdk's Broadcaster dereferences too, so a guard must drop it.
func SteakCases(topic string) []SteakCase {
	q := strconv.Quote(topic)
	literal := func(name, body string) SteakReply { return SteakReply{Body: Literal(name, []byte(body))} }
	opening := Literal("opening", []byte(`{`+q+`:{"outputsToAdmit":[`))
	oversize := Repeated("oversize", []byte(`{`), []byte(`"k":{},`), (64<<20)/7, []byte(`"k":{}}`))
	return []SteakCase{
		{Name: "null", Reply: literal("null", `null`)},
		{Name: "topic null", Reply: literal("topic null", `{`+q+`:null}`)},
		{Name: "wrong type", Reply: literal("wrong type", `{`+q+`:{"outputsToAdmit":"all"}}`)},
		{Name: "negative index", Reply: SteakReply{Body: Literal("negative", []byte(`{`+q+`:{"outputsToAdmit":[-1]}}`)), Streamed: true}},
		{Name: "index past the outputs", Reply: literal("past", `{`+q+`:{"outputsToAdmit":[4000000000]}}`)},
		{Name: "64 MiB streamed", Reply: SteakReply{Body: oversize, Streamed: true}, Oversize: true},
		{Name: "64 MiB declared", Reply: SteakReply{Body: oversize}, Oversize: true},
		{Name: "trickle below the rate floor", Reply: SteakReply{Body: opening, Rate: 100}},
		{Name: "trickle past the timeout", Reply: SteakReply{Body: opening, Rate: 50_000}},
		{Name: "honest", Reply: literal("honest", `{`+q+`:{"outputsToAdmit":[0],"coinsToRetain":[]}}`), Accepted: true},
		{Name: "unrequested topic null", Reply: literal("unrequested", `{`+q+`:{"outputsToAdmit":[0]},"tm_unrequested":null}`), Accepted: true},
	}
}
