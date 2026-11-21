package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/envelope"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

func dataReadAllocs(t *testing.T, privateCount int) float64 {
	t.Helper()
	srv := testServer(t)
	key, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	put := func(payload string, private bool, ts int64) {
		t.Helper()
		env := &envelope.Envelope{
			Type: "data", Topic: "bounded:topic", Payload: payload,
			Durable: true, Timestamp: ts, Private: private,
		}
		env.Sign(key)
		if err := srv.envelopeStore.Ingest(env); err != nil {
			t.Fatal(err)
		}
	}
	put(`{"public":true}`, false, now)
	for i := 0; i < privateCount; i++ {
		put(fmt.Sprintf(`{"private":%d}`, i), true, now+int64(i)+1)
	}

	return testing.AllocsPerRun(2, func() {
		req := httptest.NewRequest(http.MethodGet, "/data?topic=bounded:topic&limit=1", nil)
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("GET /data = %d: %s", w.Code, w.Body.String())
		}
	})
}

func TestPublicExactReadWorkDoesNotScaleWithPrivateRecords(t *testing.T) {
	baseline := dataReadAllocs(t, 0)
	withPrivate := dataReadAllocs(t, 200)
	if withPrivate > baseline+100 {
		t.Fatalf("allocations scale with private records: baseline %.0f, with private records %.0f", baseline, withPrivate)
	}
}
