package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/BSVanon/Anvil/internal/envelope"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

func TestPostCatalogDoesNotOverwriteNewerEntryWithSamePayload(t *testing.T) {
	srv := testServer(t)
	key, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	makeCatalog := func(timestamp int64) *envelope.Envelope {
		env := &envelope.Envelope{
			Type: "data", Topic: "anvil:catalog", Payload: `{"version":2}`,
			Durable: true, Timestamp: timestamp,
		}
		env.Sign(key)
		return env
	}
	newer, older := makeCatalog(200), makeCatalog(100)
	if err := srv.envelopeStore.Ingest(newer); err != nil {
		t.Fatal(err)
	}
	body, err := older.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/data", bytes.NewReader(body))
	recorder := httptest.NewRecorder()
	srv.handlePostData(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("POST /data status = %d, want %d: %s", recorder.Code, http.StatusOK, recorder.Body.String())
	}
	entries, err := srv.envelopeStore.QueryExactTopic("anvil:catalog", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Timestamp != newer.Timestamp {
		t.Fatalf("catalog entries after stale POST = %+v, want only timestamp %d", entries, newer.Timestamp)
	}
}
