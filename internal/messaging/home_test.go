package messaging

import "testing"

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
// the state — decision 2's "ordering doesn't matter" rule), with
// HasOtherHost=true for decision 3's relay row.
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

// TestHomeResolver_ExcludedHostnamesIgnored covers every exclusion in
// decision 2: localhost, 127.0.0.1, 0.0.0.0, ::1, *.local, *.example.com,
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

// TestHomeResolver_NoTopicHosted: a resolver with no AdvertSource at all
// (the node doesn't host the topic) always answers Unadvertised —
// decision 2's last bullet, and today's behaviour.
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
