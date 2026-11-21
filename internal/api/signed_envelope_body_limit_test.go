package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/BSVanon/Anvil/internal/envelope"
	ec "github.com/bsv-blockchain/go-sdk/primitives/ec"
)

type deadlineBody struct {
	closed chan struct{}
	once   sync.Once
}

func TestSignedEnvelopeAdmissionReplaysHonestBody(t *testing.T) {
	srv := testServer(t)
	key, err := ec.NewPrivateKey()
	if err != nil {
		t.Fatalf("private key: %v", err)
	}
	env := &envelope.Envelope{
		Type:      "data",
		Topic:     "test:signed-admission",
		Payload:   `{"value":"accepted"}`,
		TTL:       60,
		Timestamp: time.Now().Unix(),
	}
	env.Sign(key)
	body, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/data", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
}

func (b *deadlineBody) Read([]byte) (int, error) {
	<-b.closed
	return 0, errors.New("request read deadline reached")
}

func (b *deadlineBody) Close() error {
	b.once.Do(func() { close(b.closed) })
	return nil
}

type deadlineRecorder struct {
	*httptest.ResponseRecorder
	body *deadlineBody
}

func (w *deadlineRecorder) SetReadDeadline(time.Time) error { return w.body.Close() }

func TestSignedEnvelopeAdmissionSetsBodyReadDeadline(t *testing.T) {
	body := &deadlineBody{closed: make(chan struct{})}
	w := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder(), body: body}
	req := httptest.NewRequest(http.MethodPost, "/data", body)
	req.ContentLength = 32
	done := make(chan struct{})
	go func() {
		new(Server).authOrPay(func(http.ResponseWriter, *http.Request) {
			t.Error("partial unsigned body reached the handler")
		})(w, req)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		_ = body.Close()
		<-done
		t.Fatal("signed-envelope admission read the partial body without setting a deadline")
	}
	if w.Code != http.StatusBadRequest && w.Code != http.StatusRequestTimeout {
		t.Fatalf("status = %d, want a bounded body-read error", w.Code)
	}
}
