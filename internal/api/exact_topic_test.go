package api

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/envelope"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

// Every client read names one topic and serves that topic only. The durable
// store keys an envelope under "d:<topic>:", so a prefix scan for topic "t"
// also finds "t:x" and "t:t"; the API reads through QueryExactTopic
// (envelope/store_exact.go) instead, and so does every access decision.

// getAsClient serves GET path to an unauthenticated client, with the given
// request headers.
func getAsClient(t *testing.T, srv *Server, path string, header map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = "localhost"
	for k, v := range header {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

// dataEnvelopes decodes a GET /data response's envelopes.
func dataEnvelopes(t *testing.T, w *httptest.ResponseRecorder) []map[string]interface{} {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("GET /data: got %d %s, want 200", w.Code, w.Body.String())
	}
	var resp struct {
		Envelopes []map[string]interface{} `json:"envelopes"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode /data response: %v", err)
	}
	return resp.Envelopes
}

func TestDataQueryReturnsOnlyItsExactTopic(t *testing.T) {
	srv := testServer(t)
	base := time.Now().Unix()
	seedEnvelopeAt(t, srv.envelopeStore, "t", `{"m":"t-1"}`, base, nil)
	seedEnvelopeAt(t, srv.envelopeStore, "t", `{"m":"t-2"}`, base+1, nil)
	seedEnvelopeAt(t, srv.envelopeStore, "t:x", `{"m":"sub-x"}`, base+2, nil)
	seedEnvelopeAt(t, srv.envelopeStore, "t:t", `{"m":"sub-t"}`, base+3, nil)
	key, _ := ec.NewPrivateKey()
	eph := &envelope.Envelope{Type: "data", Topic: "t", Payload: `{"m":"t-eph"}`, TTL: 300, Timestamp: base + 4}
	eph.Sign(key)
	srv.envelopeStore.StoreEphemeralDirect(eph)

	for _, tc := range []struct {
		topic string
		want  []string // payloads, newest first
	}{
		{"t", []string{"t-eph", "t-2", "t-1"}},
		{"t:t", []string{"sub-t"}},
		{"t:x", []string{"sub-x"}},
	} {
		envs := dataEnvelopes(t, getAsClient(t, srv, "/data?topic="+tc.topic, nil))
		var got []string
		for _, e := range envs {
			if e["topic"] != tc.topic {
				t.Fatalf("GET /data?topic=%s returned an envelope on topic %v", tc.topic, e["topic"])
			}
			p, _ := e["payload"].(string)
			got = append(got, strings.TrimSuffix(strings.TrimPrefix(p, `{"m":"`), `"}`))
		}
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Fatalf("GET /data?topic=%s: got %v, want %v", tc.topic, got, tc.want)
		}
	}
}

// The node charges 100 to read the honest, unmonetized oracle:rates:bsv. A
// rule an attacker puts on the parent topic "oracle", a token naming their own
// key or a 1-sat passthrough price to their own script, opens reads of
// "oracle" only, never of oracle:rates:bsv.
func TestParentTopicRuleDoesNotServeSubtopicContent(t *testing.T) {
	attackerKey, _ := ec.NewPrivateKey()
	newSrv := func(attackerRule *envelope.Monetization) *Server {
		srv := testServer(t)
		base := time.Now().Unix()
		seedEnvelopeAt(t, srv.envelopeStore, "oracle:rates:bsv", `{"m":"honest-rate"}`, base, nil)
		seedEnvelopeAt(t, srv.envelopeStore, "oracle", `{"m":"attacker-own"}`, base+100, attackerRule)
		srv.tokenGate = NewTokenGate(NewTopicMonetizationResolver(srv.envelopeStore), true)
		srv.paymentGate = testGateWithAppPayments(t, 100, srv.envelopeStore)
		srv.mux = http.NewServeMux()
		srv.routes()
		return srv
	}
	check := func(variant string, envs []map[string]interface{}) {
		t.Helper()
		for _, e := range envs {
			if e["topic"] != "oracle" {
				t.Fatalf("%s: a read of the parent topic served an envelope on %v", variant, e["topic"])
			}
		}
		seen := payloadsByMarker(envs, "honest-rate", "attacker-own")
		if seen["honest-rate"] {
			t.Fatalf("%s: a read of the parent topic served oracle:rates:bsv's node-priced content", variant)
		}
		if !seen["attacker-own"] {
			t.Fatalf("%s: the read should serve the parent topic's own envelope", variant)
		}
	}

	srv := newSrv(tokenModel(attackerKey))
	if ch := getChallenge(t, srv, http.MethodGet, "/data?topic=oracle:rates:bsv"); ch.AmountSats != 100 {
		t.Fatalf("a direct read of oracle:rates:bsv should cost the node's 100, got %d", ch.AmountSats)
	}
	code, envs := queryWithAppToken(t, srv, "/data?topic=oracle", mintAppToken(attackerKey, "oracle"))
	if code != http.StatusOK {
		t.Fatalf("token: got %d, want 200", code)
	}
	check("token", envs)

	srv = newSrv(passthrough(otherAppScript(), 1))
	ch, envs := payAndQuery(t, srv, "/data?topic=oracle", 1)
	if ch.AmountSats != 1 || ch.PayeeLockingScriptHex != otherAppScript() {
		t.Fatalf("passthrough: the challenge should ask the attacker's 1 sat, got %d to %s", ch.AmountSats, ch.PayeeLockingScriptHex)
	}
	check("passthrough", envs)
}

// An older unmonetized envelope on P:tok, whose newest rule is token-gated,
// is P:tok's content: a direct read of P:tok asks for the token, and a read
// of the parent topic P does not serve it either.
func TestParentTopicReadDoesNotServeTokenGatedSubtopicHistory(t *testing.T) {
	srv := testServer(t)
	appKey, _ := ec.NewPrivateKey()
	base := time.Now().Unix()
	seedEnvelopeAt(t, srv.envelopeStore, "P:tok", `{"m":"older-unpriced"}`, base, nil)
	seedEnvelopeAt(t, srv.envelopeStore, "P:tok", `{"m":"gated"}`, base+100, tokenModel(appKey))
	srv.tokenGate = NewTokenGate(NewTopicMonetizationResolver(srv.envelopeStore), true)
	srv.mux = http.NewServeMux()
	srv.routes()

	if w := getAsClient(t, srv, "/data?topic=P:tok", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("a direct read of P:tok without a token: got %d, want 401", w.Code)
	}
	if envs := dataEnvelopes(t, getAsClient(t, srv, "/data?topic=P", nil)); len(envs) != 0 {
		t.Fatalf("a read of P, which has no envelopes of its own, served P:tok's: %v", envs)
	}
}

// /identity/{pubkey} reads identity:<pubkey>, and /topics/{topic} takes its
// metadata from meta:<topic>, never from a newer envelope on a sub-topic such
// as identity:<pubkey>:x or meta:<topic>:x (the metadata of topic <topic>:x).
func TestIdentityAndMetadataReadOnlyTheirExactTopic(t *testing.T) {
	srv := testServer(t)
	key, _ := ec.NewPrivateKey()
	pub := hex.EncodeToString(key.PubKey().Compressed())
	base := time.Now().Unix()
	seedEnvelopeAt(t, srv.envelopeStore, "identity:"+pub, `{"name":"real-profile"}`, base, nil)
	seedEnvelopeAt(t, srv.envelopeStore, "identity:"+pub+":x", `{"name":"sub-topic-profile"}`, base+100, nil)
	seedEnvelopeAt(t, srv.envelopeStore, "feed", `{"m":"feed"}`, base, nil)
	seedEnvelopeAt(t, srv.envelopeStore, "meta:feed", `{"description":"real-meta"}`, base, nil)
	seedEnvelopeAt(t, srv.envelopeStore, "meta:feed:x", `{"description":"sub-topic-meta"}`, base+100, nil)

	if w := getAsClient(t, srv, "/identity/"+pub, nil); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "real-profile") {
		t.Fatalf("GET /identity/{pubkey}: got %d %s, want identity:<pubkey>'s own profile", w.Code, w.Body.String())
	}
	if w := getAsClient(t, srv, "/topics/feed", nil); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "real-meta") {
		t.Fatalf("GET /topics/feed: got %d %s, want meta:feed's own metadata", w.Code, w.Body.String())
	}
}

// /topics/{topic} counts, dates and prices the topic's own envelopes only.
func TestTopicDetailAggregatesOnlyItsExactTopic(t *testing.T) {
	srv := testServer(t)
	base := time.Now().Unix()
	seedEnvelopeAt(t, srv.envelopeStore, "feed", `{"m":"feed"}`, base, passthrough(appPayeeScript(), 10))
	seedEnvelopeAt(t, srv.envelopeStore, "feed:x", `{"m":"sub"}`, base+100, passthrough(otherAppScript(), 999))

	w := getAsClient(t, srv, "/topics/feed", nil)
	var resp struct {
		Topic TopicInfo `json:"topic"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil || w.Code != http.StatusOK {
		t.Fatalf("GET /topics/feed: got %d (%v)", w.Code, err)
	}
	if got := resp.Topic; got.Count != 1 || got.Price != 10 || got.LastUpdated != base {
		t.Fatalf("GET /topics/feed: got count=%d price=%d last_updated=%d, want feed's own 1, 10, %d", got.Count, got.Price, got.LastUpdated, base)
	}
}

// /app/{name} and /explorer redirect from listings on anvil:catalog only; a
// listing on a sub-topic such as anvil:catalog:x is not in the catalog.
func TestAppRedirectReadsOnlyTheCatalogTopic(t *testing.T) {
	srv := testServer(t)
	base := time.Now().Unix()
	listing := func(origin string) string {
		return `{"name":"Anvil Explorer","content_origin":"` + origin + `"}`
	}
	seedEnvelopeAt(t, srv.envelopeStore, "anvil:catalog:x", listing("sub_topic_origin"), base+100, nil)
	paths := []string{"/app/Anvil%20Explorer", "/explorer"}
	for _, path := range paths {
		if w := getAsClient(t, srv, path, nil); w.Code != http.StatusNotFound {
			t.Fatalf("%s with no catalog listing: got %d to %q, want 404", path, w.Code, w.Header().Get("Location"))
		}
	}
	seedEnvelopeAt(t, srv.envelopeStore, "anvil:catalog", listing("catalog_origin"), base, nil)
	for _, path := range paths {
		w := getAsClient(t, srv, path, nil)
		if w.Code != http.StatusFound || w.Header().Get("Location") != "/content/catalog_origin" {
			t.Fatalf("%s: got %d to %q, want 302 to the catalog's own listing", path, w.Code, w.Header().Get("Location"))
		}
	}
}

// /mesh/nodes takes heartbeats from mesh:heartbeat only; an envelope on a
// sub-topic such as mesh:heartbeat:x is not a node's heartbeat.
func TestMeshNodesReadOnlyTheHeartbeatTopic(t *testing.T) {
	srv := testServer(t)
	heartbeat := func(name string) string {
		return `{"node":"` + name + `","version":"0.5.3","height":100,"peers":1}`
	}
	base := time.Now().Unix()
	seedEnvelopeAt(t, srv.envelopeStore, "mesh:heartbeat", heartbeat("honest-node"), base, nil)
	seedEnvelopeAt(t, srv.envelopeStore, "mesh:heartbeat:x", heartbeat("sub-topic-node"), base+100, nil)

	w := getAsClient(t, srv, "/mesh/nodes", nil)
	var resp struct {
		Nodes []MeshNode `json:"nodes"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil || w.Code != http.StatusOK {
		t.Fatalf("GET /mesh/nodes: got %d (%v)", w.Code, err)
	}
	names := map[string]bool{}
	for _, n := range resp.Nodes {
		names[n.Name] = true
	}
	if !names["honest-node"] || names["sub-topic-node"] {
		t.Fatalf("GET /mesh/nodes: want the mesh:heartbeat node only, got %v", names)
	}
}
