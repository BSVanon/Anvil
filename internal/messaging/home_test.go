package messaging

import (
	"strings"
	"testing"
)

func sourceFor(hosts ...string) AdvertSource {
	ads := make([]Advert, 0, len(hosts))
	for _, h := range hosts {
		ads = append(ads, Advert{Host: h})
	}
	return func(string) ([]Advert, error) { return ads, nil }
}

// TestHomeResolver_Home: an advert naming one of this node's own hosts
// answers Home.
func TestHomeResolver_Home(t *testing.T) {
	r := NewHomeResolver([]string{"https://anvil.example"}, sourceFor("https://anvil.example"))
	res, err := r.Resolve("deadbeef")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.State != Home {
		t.Fatalf("expected Home, got %s", res.State)
	}
	if res.HasOtherHost {
		t.Fatalf("expected HasOtherHost=false with a single matching advert")
	}
}

// TestHomeResolver_Elsewhere: adverts exist, but none names this node.
func TestHomeResolver_Elsewhere(t *testing.T) {
	r := NewHomeResolver([]string{"https://anvil.example"}, sourceFor("https://other.example"))
	res, err := r.Resolve("deadbeef")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.State != Elsewhere {
		t.Fatalf("expected Elsewhere, got %s", res.State)
	}
}

// TestHomeResolver_Unadvertised: no adverts at all.
func TestHomeResolver_Unadvertised(t *testing.T) {
	r := NewHomeResolver([]string{"https://anvil.example"}, sourceFor())
	res, err := r.Resolve("deadbeef")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.State != Unadvertised {
		t.Fatalf("expected Unadvertised, got %s", res.State)
	}
}

// TestHomeResolver_HomeAndElsewhere: a recipient advertising BOTH this
// node and another host is Home (ordering/co-occurrence doesn't change
// the state), with HasOtherHost=true for the "Forward received, Home"
// relay row.
func TestHomeResolver_HomeAndElsewhere(t *testing.T) {
	r := NewHomeResolver([]string{"https://anvil.example"},
		sourceFor("https://other.example", "https://anvil.example"))
	res, err := r.Resolve("deadbeef")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.State != Home {
		t.Fatalf("expected Home, got %s", res.State)
	}
	if !res.HasOtherHost {
		t.Fatal("expected HasOtherHost=true when another qualifying host is also advertised")
	}
}

// TestHomeResolver_HTTPOnlyAdvertIgnored: a plain-http advert never
// qualifies, even if its host string otherwise matches this node.
func TestHomeResolver_HTTPOnlyAdvertIgnored(t *testing.T) {
	r := NewHomeResolver([]string{"https://anvil.example"}, sourceFor("http://anvil.example"))
	res, err := r.Resolve("deadbeef")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.State != Unadvertised {
		t.Fatalf("expected Unadvertised (http advert must be ignored), got %s", res.State)
	}
}

// TestHomeResolver_ExcludedHostnamesIgnored covers every exclusion the
// Home Rule applies: localhost, 127.0.0.1, 0.0.0.0, ::1, *.local, *.example.com,
// *.test, *.invalid, *.localhost never qualify.
func TestHomeResolver_ExcludedHostnamesIgnored(t *testing.T) {
	excluded := []string{
		"https://localhost",
		"https://127.0.0.1",
		"https://0.0.0.0",
		"https://[::1]",
		"https://box.local",
		"https://foo.example.com",
		"https://site.test",
		"https://host.invalid",
		"https://dev.localhost",
	}
	for _, host := range excluded {
		t.Run(host, func(t *testing.T) {
			r := NewHomeResolver(nil, sourceFor(host))
			res, err := r.Resolve("deadbeef")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if res.State != Unadvertised {
				t.Fatalf("expected Unadvertised for excluded host %s, got %s", host, res.State)
			}
		})
	}
}

// TestHomeResolver_URLNormalisation confirms a default port, trailing
// slash, and scheme/host case are all normalised away before comparison,
// while the path's case is preserved.
func TestHomeResolver_URLNormalisation(t *testing.T) {
	cases := []struct {
		name     string
		ownHost  string
		advert   string
		wantHome bool
	}{
		{"default port dropped", "https://anvil.example", "https://anvil.example:443", true},
		{"trailing slash dropped", "https://anvil.example", "https://anvil.example/", true},
		{"scheme+host case-insensitive", "https://Anvil.Example", "https://anvil.example", true},
		{"non-default port kept, differs", "https://anvil.example", "https://anvil.example:8443", false},
		{"path kept, differs", "https://anvil.example/a", "https://anvil.example/b", false},
		{"path case preserved, differs", "https://anvil.example/MsgBox", "https://anvil.example/msgbox", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := NewHomeResolver([]string{c.ownHost}, sourceFor(c.advert))
			res, err := r.Resolve("deadbeef")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			gotHome := res.State == Home
			if gotHome != c.wantHome {
				t.Fatalf("own=%s advert=%s: want home=%v got state=%s", c.ownHost, c.advert, c.wantHome, res.State)
			}
		})
	}
}

// TestHomeResolver_SeveralAdvertsAtOnce: several distinct non-matching
// adverts still correctly answer Elsewhere (not Home, not Unadvertised).
func TestHomeResolver_SeveralAdvertsAtOnce(t *testing.T) {
	r := NewHomeResolver([]string{"https://anvil.example"},
		sourceFor("https://a.example", "https://b.example", "https://c.example"))
	res, err := r.Resolve("deadbeef")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.State != Elsewhere {
		t.Fatalf("expected Elsewhere, got %s", res.State)
	}
}

// TestQualifyAndNormalise_HostFilterTable is the reviewer's probe
// (scratchpad/repro/messaging_zz_review_test.go.txt) made permanent as a
// real assertion test: every row of the host-filter table below,
// proved against Node 22's WHATWG `URL`.
// TestQualifyAndNormalise_InvalidUTF8HostNotCounted: a host string
// containing a byte sequence that cannot be valid UTF-8 never qualifies.
// Admission admits such an advert now (matching canon's non-fatal
// decode, topics/messagebox_test.go's
// TestMessageBoxAdmit_InvalidUTF8HostAdmitted); this is the layer that
// keeps it from being usable.
func TestQualifyAndNormalise_InvalidUTF8HostNotCounted(t *testing.T) {
	raw := "https://" + string([]byte{0xff, 0xfe, 0xfd})
	if _, ok := qualifyAndNormalise(raw); ok {
		t.Fatalf("expected a host with invalid UTF-8 bytes to never qualify, raw=%q", raw)
	}
}

func TestQualifyAndNormalise_HostFilterTable(t *testing.T) {
	// IPv4 numeric forms: three different spellings of the loopback
	// address must all be excluded, matching canon ("excluded, hostname
	// becomes 127.0.0.1" — table row 1). 127.0.0.1 itself is the
	// pre-existing baseline, unaffected by this fix, included so the
	// alternate spellings are seen converging on the same answer.
	for _, h := range []string{"https://127.1", "https://0x7f000001", "https://2130706433", "https://127.0.0.1"} {
		if _, ok := qualifyAndNormalise(h); ok {
			t.Errorf("%s: expected excluded (an alternate spelling of the loopback address), got qualified", h)
		}
	}

	// [::1]: canon COUNTS this — a canon bug, since isLocalHostname's
	// own IPv6 check never strips the brackets from the string it's
	// actually given (host.ts:28-29), so the literal "::1" comparison
	// never fires. The overseer decision is to keep excluding it here
	// anyway, a deliberate, documented divergence (table row 2).
	if _, ok := qualifyAndNormalise("https://[::1]"); ok {
		t.Error("https://[::1]: expected excluded (Anvil's deliberate divergence from the canon bug), got qualified")
	}

	// Ports: ":0443" must drop exactly like ":443" (table row 3 —
	// parsed as a number, not string-compared against the literal
	// "443").
	withLeadingZero, ok := qualifyAndNormalise("https://node-a.example.org:0443")
	if !ok {
		t.Fatal("https://node-a.example.org:0443: expected to qualify")
	}
	plain, ok := qualifyAndNormalise("https://node-a.example.org:443")
	if !ok {
		t.Fatal("https://node-a.example.org:443: expected to qualify")
	}
	if withLeadingZero != plain || withLeadingZero != "https://node-a.example.org" {
		t.Fatalf(":0443 should normalise identically to :443 (both the default port): got %q and %q", withLeadingZero, plain)
	}

	// IDN hosts: converted to ASCII/punycode, matching canon, so both
	// spellings of the same hostname normalise to the same string
	// (table row 4).
	idn, ok := qualifyAndNormalise("https://bücher.example")
	if !ok {
		t.Fatal("https://bücher.example: expected to qualify")
	}
	punycode, ok := qualifyAndNormalise("https://xn--bcher-kva.example")
	if !ok {
		t.Fatal("https://xn--bcher-kva.example: expected to qualify")
	}
	if idn != punycode || idn != "https://xn--bcher-kva.example" {
		t.Fatalf("an IDN host should normalise to the same punycode form as its already-ASCII spelling: got %q and %q", idn, punycode)
	}

	// IPv6 brackets: dropping them on normalise made two DIFFERENT hosts
	// collide (the review's own example, cited alongside the table).
	// They must stay distinct, and the normalised form must still be
	// bracketed.
	a, ok := qualifyAndNormalise("https://[a::1]:8443")
	if !ok {
		t.Fatal("https://[a::1]:8443: expected to qualify")
	}
	b, ok := qualifyAndNormalise("https://[a::1:8443]")
	if !ok {
		t.Fatal("https://[a::1:8443]: expected to qualify")
	}
	if a == b {
		t.Fatalf("[a::1]:8443 and [a::1:8443] must stay distinct hosts, both normalised to %q", a)
	}
	if !strings.HasPrefix(a, "https://[") {
		t.Fatalf("expected IPv6 brackets preserved in the normalised form, got %q", a)
	}
}

// TestHomeResolver_HostsDedupedAfterNormalise: two raw advert host
// strings that normalise to the SAME qualifying host count as one host,
// not two — the recipient must still answer Home (not just "some other
// host"), and HasOtherHost must not be set from a duplicate of this
// node's own host arriving under a different raw spelling.
func TestHomeResolver_HostsDedupedAfterNormalise(t *testing.T) {
	r := NewHomeResolver([]string{"https://anvil.example"},
		sourceFor("https://anvil.example", "https://ANVIL.EXAMPLE/", "https://anvil.example:443"))
	res, err := r.Resolve("deadbeef")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.State != Home {
		t.Fatalf("expected Home, got %s", res.State)
	}
	if res.HasOtherHost {
		t.Fatal("expected HasOtherHost=false: all three adverts normalise to this node's own single host")
	}
}

// TestHomeResolver_NoTopicHosted: a resolver with no AdvertSource at all
// (the node doesn't host the topic) always answers Unadvertised,
// today's behaviour.
func TestHomeResolver_NoTopicHosted(t *testing.T) {
	r := NewHomeResolver([]string{"https://anvil.example"}, nil)
	res, err := r.Resolve("deadbeef")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.State != Unadvertised {
		t.Fatalf("expected Unadvertised with nil AdvertSource, got %s", res.State)
	}

	res, err = AlwaysUnadvertised.Resolve("deadbeef")
	if err != nil || res.State != Unadvertised {
		t.Fatalf("AlwaysUnadvertised: state=%s err=%v", res.State, err)
	}
}
