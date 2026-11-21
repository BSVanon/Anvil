package api

import (
	"bytes"
	"io"
	"net/http"

	"github.com/BSVanon/Anvil/internal/overlay/routeguard"
)

const maxSignedEnvelopeBody int64 = 1 << 20

var signedEnvelopeRoute = routeguard.Route{
	MaxBody:     maxSignedEnvelopeBody,
	Expansion:   8,
	Allowance:   2 << 20,
	ReadTimeout: routeguard.JSONReadTimeout,
}

// readSignedEnvelopeBody admits and reads the unauthenticated credential
// fallback under the same process-wide memory, read-count, arrival deadline,
// and minimum-rate guard as the public overlay routes.
func readSignedEnvelopeBody(w http.ResponseWriter, r *http.Request) (*routeguard.Ticket, []byte, bool) {
	ticket, err := routeguard.Default().Begin(w, r, true)
	if err != nil {
		routeguard.Refuse(w, r)
		writeSignedEnvelopeReadError(w, err)
		return nil, nil, false
	}
	body, err := ticket.ReadBody(w, r, signedEnvelopeRoute)
	if err != nil {
		ticket.Close()
		writeSignedEnvelopeReadError(w, err)
		return nil, nil, false
	}
	return ticket, body, true
}

func writeSignedEnvelopeReadError(w http.ResponseWriter, err error) {
	status, message := routeguard.BodyStatus(err, "read signed envelope: ")
	if status == http.StatusServiceUnavailable {
		routeguard.SetRetryAfter(w)
	}
	writeError(w, status, message)
}

func replayRequestBody(r *http.Request, body []byte) {
	r.Body = io.NopCloser(bytes.NewReader(body))
}
