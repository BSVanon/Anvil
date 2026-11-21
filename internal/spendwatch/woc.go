package spendwatch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// WhatsOnChain's spent-output endpoint, GET {base}/tx/{txid}/{vout}/spent
// (the "(Un)Spent Transaction Outputs" section of the WhatsOnChain API
// docs). A spent output answers 200 with the spending input,
// {"txid":"<spending txid>","vin":<input index>,"status":"confirmed"}; an
// unspent one answers 404.
const defaultWoCBase = "https://api.whatsonchain.com/v1/bsv/main"

// maxSpentReplyBytes caps a spent-output reply. The real one is about a
// hundred bytes.
const maxSpentReplyBytes = 64 << 10

// errRateLimited is a 429 from WhatsOnChain. The limiter has already pushed
// the next request back when a caller sees it.
var errRateLimited = errors.New("WhatsOnChain rate limit (429)")

// spentReply is the spent-output endpoint's 200 body.
type spentReply struct {
	TxID   string `json:"txid"`
	Vin    int    `json:"vin"`
	Status string `json:"status"`
}

// answer is one spent-output lookup's result.
type answer struct {
	spent     bool
	txid      string
	confirmed bool
}

// limiter spaces every WhatsOnChain request this package makes, polls and
// one-shot checks alike, at least gap apart, and holds them all back after a
// 429: for the reply's Retry-After when it gives one, else for a backoff
// that starts at backoffBase and doubles up to backoffMax, reset by the
// next success.
type limiter struct {
	gap         time.Duration
	backoffBase time.Duration
	backoffMax  time.Duration

	mu      sync.Mutex
	next    time.Time     // earliest start of the next request
	backoff time.Duration // the backoff the next 429 applies
}

// wait blocks until a request may start, then reserves its slot.
func (l *limiter) wait(ctx context.Context) error {
	for {
		l.mu.Lock()
		now := time.Now()
		if !now.Before(l.next) {
			l.next = now.Add(l.gap)
			l.mu.Unlock()
			return nil
		}
		delay := l.next.Sub(now)
		l.mu.Unlock()
		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}

// rateLimited pushes every later request back after a 429.
func (l *limiter) rateLimited(retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.backoff <= 0 {
		l.backoff = l.backoffBase
	}
	hold := l.backoff
	if retryAfter > hold {
		hold = retryAfter
	}
	if until := time.Now().Add(hold); until.After(l.next) {
		l.next = until
	}
	l.backoff *= 2
	if l.backoff > l.backoffMax {
		l.backoff = l.backoffMax
	}
}

// succeeded resets the 429 backoff.
func (l *limiter) succeeded() {
	l.mu.Lock()
	l.backoff = 0
	l.mu.Unlock()
}

// wocClient asks WhatsOnChain whether an outpoint is spent.
type wocClient struct {
	base   string
	client *http.Client
	lim    *limiter
}

// spent looks up txid:vout through the limiter.
func (c *wocClient) spent(ctx context.Context, txid string, vout uint32) (answer, error) {
	if err := c.lim.wait(ctx); err != nil {
		return answer{}, err
	}
	url := fmt.Sprintf("%s/tx/%s/%d/spent", c.base, txid, vout)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return answer{}, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return answer{}, fmt.Errorf("spent lookup: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSpentReplyBytes+1))
	if err != nil {
		return answer{}, fmt.Errorf("read spent reply: %w", err)
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		c.lim.succeeded()
		return answer{}, nil
	case http.StatusTooManyRequests:
		c.lim.rateLimited(retryAfter(resp.Header.Get("Retry-After")))
		return answer{}, errRateLimited
	default:
		return answer{}, fmt.Errorf("spent lookup: HTTP %d", resp.StatusCode)
	}
	if len(body) > maxSpentReplyBytes {
		return answer{}, fmt.Errorf("spent reply exceeds %d bytes", maxSpentReplyBytes)
	}
	var r spentReply
	if err := json.Unmarshal(body, &r); err != nil {
		return answer{}, fmt.Errorf("decode spent reply: %w", err)
	}
	if !isTxid(r.TxID) {
		return answer{}, fmt.Errorf("spent reply names no valid txid")
	}
	c.lim.succeeded()
	return answer{spent: true, txid: r.TxID, confirmed: r.Status == "confirmed"}, nil
}

// retryAfter reads a Retry-After header given in seconds.
func retryAfter(v string) time.Duration {
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0
	}
	if n > 3600 {
		n = 3600
	}
	return time.Duration(n) * time.Second
}

// isTxid reports whether s is 64 lowercase or uppercase hex characters.
func isTxid(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}
