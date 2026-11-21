package api

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/netguard/bodyread"
)

// useBodyShare runs the test with a client share of n body reads.
func useBodyShare(t *testing.T, n int) {
	t.Helper()
	prev := paymentBodyShares
	paymentBodyShares = newBodyShares(n)
	t.Cleanup(func() { paymentBodyShares = prev })
}

// TestBodySharesCountEachClient: a key takes at most its limit, keys count
// apart, a leave gives back one place and only once, and a key with no read
// left is dropped.
func TestBodySharesCountEachClient(t *testing.T) {
	s := newBodyShares(2)
	leaveA1, ok1 := s.take("a")
	leaveA2, ok2 := s.take("a")
	if !ok1 || !ok2 {
		t.Fatal("a client was refused within its share")
	}
	if _, ok := s.take("a"); ok {
		t.Fatal("a client took a third read with a share of 2")
	}
	leaveB, ok := s.take("b")
	if !ok {
		t.Fatal("another client was refused while the first held its share")
	}
	leaveA1()
	leaveA1()
	if n := s.holding("a"); n != 1 {
		t.Fatalf("after one read ended, twice over: the client holds %d, want 1", n)
	}
	leaveA3, ok := s.take("a")
	if !ok {
		t.Fatal("a client was refused after one of its reads ended")
	}
	leaveA2()
	leaveA3()
	leaveB()
	if n := s.clients(); n != 0 {
		t.Fatalf("%d clients are still counted after every read ended, want 0", n)
	}
}

// chargingServerConfig is a server config that charges 100 sats, with the
// trust_proxy settings trust and hops.
func chargingServerConfig(t *testing.T, trust bool, hops int) ServerConfig {
	return ServerConfig{PaymentSatoshis: 100, PayeeScriptHex: testPayeeScript(t), NonceProvider: &DevNonceProvider{},
		TrustProxy: trust, TrustProxyHops: hops}
}

// TestPaymentGateKeysClientsAsTheRateLimiter: the server's gate counts a
// client under the rate limiter's key, with the server's trust_proxy
// settings, so one client is one client to both; a gate built without them
// keys as trust_proxy off.
func TestPaymentGateKeysClientsAsTheRateLimiter(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/data", nil)
	req.RemoteAddr = "192.0.2.10:5000"
	req.Header.Set("X-Forwarded-For", "198.51.100.1, 203.0.113.9")
	for _, tc := range []struct {
		trust bool
		hops  int
		want  string
	}{
		{false, 1, "192.0.2.10"}, // a remote peer's X-Forwarded-For is not trusted
		{true, 1, "203.0.113.9"},
		{true, 2, "198.51.100.1"},
	} {
		pg := newServerPaymentGate(chargingServerConfig(t, tc.trust, tc.hops), nil)
		if got := pg.clientKeyFor(req); got != rateLimitKey(clientIP(req, tc.trust, tc.hops)) || got != tc.want {
			t.Fatalf("trust_proxy=%v hops=%d: key %q, want %q", tc.trust, tc.hops, got, tc.want)
		}
	}
	if got := testGate(t, 100).clientKeyFor(req); got != "192.0.2.10" {
		t.Fatalf("a gate built without the server's settings: key %q, want 192.0.2.10", got)
	}
	one, two := req.Clone(req.Context()), req.Clone(req.Context())
	one.Header.Set("X-Forwarded-For", "2001:db8:1:2::5")
	two.Header.Set("X-Forwarded-For", "2001:db8:1:2::6")
	pg := newServerPaymentGate(chargingServerConfig(t, true, 1), nil)
	if pg.clientKeyFor(one) != pg.clientKeyFor(two) {
		t.Fatal("two addresses in one IPv6 /64 must be one client, as the rate limiter counts them")
	}
}

// TestPaymentBodyClientShareRefusesOnlyThatClient: with
// paymentBodyClientShare bodies of one client stalled in their reads, its
// next body is answered 503 with ERR_PAYMENT_BODY_SHARE and a Retry-After,
// though permits are free, while another client's body still takes one. Once
// one of the first client's bodies ends, that client may send another.
func TestPaymentBodyClientShareRefusesOnlyThatClient(t *testing.T) {
	shrinkPaymentBodyGrace(t, 5*time.Second) // no stalled body is cut off during the test
	srv := testServerWithPaymentGate(t, 100)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close) // after the stalled bodies' own cleanups end them
	const greedy, other = "203.0.113.7", "198.51.100.8"

	firstBody, firstDone := postStalledAs(t, ts.URL+"/data", greedy, nil)
	for i := 1; i < paymentBodyClientShare; i++ {
		postStalledAs(t, ts.URL+"/data", greedy, nil)
	}
	eventually(t, 5*time.Second, func() bool { return paymentBodyReads.InUse() == paymentBodyClientShare })

	_, over := postStalledAs(t, ts.URL+"/data", greedy, nil)
	select {
	case res := <-over:
		var body codedError
		if res.resp == nil || res.resp.StatusCode != http.StatusServiceUnavailable ||
			json.Unmarshal(res.body, &body) != nil || body.Code != codePaymentBodyShare {
			t.Fatalf("a body past the client's share: got %+v %s, want 503 with code %s", res.resp, res.body, codePaymentBodyShare)
		}
		if got := res.resp.Header.Get("Retry-After"); got != "5" {
			t.Fatalf("a body past the client's share: Retry-After %q, want the grace, 5", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a body past the client's share was not refused")
	}

	postStalledAs(t, ts.URL+"/data", other, nil)
	eventually(t, 5*time.Second, func() bool { return paymentBodyReads.InUse() == paymentBodyClientShare+1 })

	firstBody.Close()
	wantStatus(t, firstDone, http.StatusPaymentRequired, 5*time.Second)
	key := rateLimitKey(greedy)
	eventually(t, 5*time.Second, func() bool { return paymentBodyShares.holding(key) == paymentBodyClientShare-1 })
	postStalledAs(t, ts.URL+"/data", greedy, nil)
	eventually(t, 5*time.Second, func() bool { return paymentBodyShares.holding(key) == paymentBodyClientShare })
}

// TestStalledBodiesFromOneClientLeavePermitsForOthers: a client that keeps
// re-opening bodies that send nothing holds at most its share of the
// permits, so another client's bodies are still read and challenged. Scaled
// down: 4 permits, a share of 2 and a 300 ms grace.
func TestStalledBodiesFromOneClientLeavePermitsForOthers(t *testing.T) {
	shrinkPaymentBodyGrace(t, 300*time.Millisecond)
	usePaymentBodyPermits(t, 4)
	useBodyShare(t, 2)
	srv := testServerWithPaymentGate(t, 100)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	addr := strings.TrimPrefix(ts.URL, "http://")
	const attacker = "203.0.113.66"

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ { // three times the permits: holders, and a queue ahead of the honest client
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				c, err := net.Dial("tcp", addr)
				if err != nil {
					return
				}
				_, _ = io.WriteString(c, "POST /data HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: "+attacker+"\r\nContent-Length: 1000\r\n\r\n")
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				_, _ = c.Read(make([]byte, 512)) // wait for the refusal, then open another
				c.Close()
			}
		}()
	}
	defer func() { close(stop); wg.Wait() }()
	eventually(t, 5*time.Second, func() bool { return paymentBodyShares.holding(attacker) == 2 })

	for i := 0; i < 10; i++ {
		resp, err := http.Post(ts.URL+"/data", "application/json", strings.NewReader(`{"x":1}`))
		if err != nil {
			t.Fatalf("honest POST /data %d: %v", i, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusPaymentRequired {
			t.Fatalf("honest POST /data %d while another client stalls bodies: got %d, want its 402 challenge", i, resp.StatusCode)
		}
	}
}

// TestPaymentBodyKeepsTheSharedFloor: a payment body is paced at
// paymentBodyMinRate, half bodyread.MinReadRate, with the read's timeout the
// time a 1 MiB body takes at that rate. A body that arrives at 20 KiB/s past
// the grace, over that floor and under bodyread.MinReadRate, is read in full.
func TestPaymentBodyKeepsTheSharedFloor(t *testing.T) {
	l := paymentBodyLimits
	if l.MinRate != bodyread.MinReadRate/2 || l.Grace != bodyread.ReadGrace ||
		l.Timeout != l.Grace+time.Duration(l.Max)*time.Second/time.Duration(l.MinRate) {
		t.Fatalf("payment body limits %+v, want a floor of %d bytes a second after %v, and a timeout of a 1 MiB body at it", l, bodyread.MinReadRate/2, bodyread.ReadGrace)
	}
	shrinkPaymentBodyGrace(t, 300*time.Millisecond)
	srv := testServerWithPaymentGate(t, 100)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	pw, done := postStalled(t, ts.URL+"/data", nil)
	go func() {
		// Chunk k of 4 KiB goes out 200k ms after the first, on a fixed clock:
		// 20 KiB/s. The floor wants it by 300 + 250k ms, and
		// bodyread.MinReadRate would want it by 300 + 125k ms, which chunk 5
		// already misses.
		chunk := make([]byte, 4<<10)
		start := time.Now()
		for k := 0; k < 12; k++ {
			time.Sleep(time.Until(start.Add(time.Duration(k) * 200 * time.Millisecond)))
			_, _ = pw.Write(chunk)
		}
		pw.Close()
	}()
	wantStatus(t, done, http.StatusPaymentRequired, 10*time.Second)
}
