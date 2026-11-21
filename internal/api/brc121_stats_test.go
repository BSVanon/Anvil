package api

import (
	"encoding/json"
	"net/http"
	"testing"
)

// TestBRC121StatsOperatorOnly: /stats shows the BRC-121 block, with the
// journal's size and cap, to the operator only.
func TestBRC121StatsOperatorOnly(t *testing.T) {
	srv, _, _ := brc121Server(t)
	srv.paymentGate.endpointPrices = map[string]int{"/stats": 0}
	rebuildRoutes(srv)
	read := func(h map[string]string) map[string]interface{} {
		w := getWithHeaders(srv, "/stats", h)
		if w.Code != http.StatusOK {
			t.Fatalf("/stats: %d %s", w.Code, w.Body.String())
		}
		var out map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if _, ok := read(nil)["brc121"]; ok {
		t.Fatal("a caller who is not the operator must not see the BRC-121 block")
	}
	b, _ := read(map[string]string{"Authorization": "Bearer test-token"})["brc121"].(map[string]interface{})
	j, _ := b["journal"].(map[string]interface{})
	if b["offered"] != true || j["cap"] != float64(maxBRC121JournalEntries) || j["entries"] != float64(0) {
		t.Fatalf("the operator's BRC-121 block: %v", b)
	}
}
